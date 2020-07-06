Return-Path: <kasan-dev+bncBDGPTM5BQUDRBSUXRP4AKGQEIKE2QSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe39.google.com (mail-vs1-xe39.google.com [IPv6:2607:f8b0:4864:20::e39])
	by mail.lfdr.de (Postfix) with ESMTPS id 88A252152D1
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Jul 2020 08:59:23 +0200 (CEST)
Received: by mail-vs1-xe39.google.com with SMTP id l26sf273482vsb.23
        for <lists+kasan-dev@lfdr.de>; Sun, 05 Jul 2020 23:59:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1594018762; cv=pass;
        d=google.com; s=arc-20160816;
        b=JnhGY/x7W1HiurC0vHydfMoTTnY73a5UssmbhN2Kwy4MV8vEkw+A78E7tsNtxT7qzQ
         4sSexaVsDwK7PIbAM5j/qFKH0lbcXV3E894gJyinTQ+Rs7BDSdboqZQoLFi8uHyfNMq7
         hsK+H/KgX/GlaV5IkfoZYuOlcl8uBlySWcdG0SXtXwNtIXjevXd1H91Sq7rdHHDtM99v
         FEDQ1y/jIQDorqGUNukf1p0iv1COrTkz0lQ0qmVOiSax7gR169Rk1biA9mdbEd9zrKr2
         bNqda9iiMEgqxQq8OzkKSFsubxiRv5vnt3zOHjexBMTQhAclkuFwIc6/gcTh/t0slBDj
         VBcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:date:cc:to:from:subject
         :message-id:sender:dkim-signature;
        bh=ecD04ySvnQfO8M7akJjGLlCi/Ir3tlqoQY5Az70thAc=;
        b=ulYaUUcE/9Lb6vl3vvuDAc8w/knbyNPxAWKh0NfnvR4Dcr+zYxhqTG506gqWr0tk5t
         E4B0mvRmLeTjMZWA0xbBdQlm+6UTawgdwiEOKq/jbUUwKfHzZjVPsi4YicuWPapPeQhn
         zvpfbaALeHgi7HxB0qMUtVPYLePvdo37XpMNz/27+2ml2vtHx8+AYVSuQ5Fzf4jWSVgl
         6k7Wk85GY9scsIQBEEqRYq4czZSxqX/Sftl9t1Z2MnUBANHHpn9f2SYB2eAIANHKrL+x
         bZU/3z/2FYC8ecYir6JOE5FbRZqNO0wy1/ltjSRL/Iz4bJ2cJXYrlqqaGNQxzamlfhpi
         qYhw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=ZWXHNQeH;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ecD04ySvnQfO8M7akJjGLlCi/Ir3tlqoQY5Az70thAc=;
        b=HjCBRv6BRHMSKn61FuWVv5hU0Tdbh1nKHCTBzqg++zR8SDedMM+ip5Xg7M3R5pjl7o
         kO+nuvd19ugdwr/xvSRuthO3dOAL9lVRkkOVGeENZh4kWI3Es4VTLqIEZhUw2E1pd7tz
         fCIYrsIjc3ps1s8tP7X/UqfvIFItGoRT5M5arYr4l+BIUICQcJeBY4dl+6hqOhS5BEpq
         P6fTrFLF4G05PxEwLwZNB+ue82xyPXkPvvT9pAWHzl3YpTIbLEjmsLER0iugvfJaE1Wa
         OXFVg3Jh2UU9l9sV2gucThzJ6IfGYKwUSKT6R7msR78eb4/GQ9gt+26JHZQgS92iXe+v
         1uRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ecD04ySvnQfO8M7akJjGLlCi/Ir3tlqoQY5Az70thAc=;
        b=tix9t2VVEnMNNpdFQB6CPeuyBq9YC+tdHsx4IIb5V5xSw0OZ18ZpMv92Ui80J8JdPe
         cOzvZBiLYXDotU22i3ca2j2dTcpONz7u8U5joqqJlKY3W1MQPmMJ9X1MBPlZ6eVKrgBG
         EZTXk/PmkoW9WegKhPDDlqmK6Yj6fK1bL/vnU+qPeCLApcjQ0NTrgZ4QKn8Xj8aVw1qD
         WMCVxHnHfyhC/H8YCX8LIBSzLlyQlmOEIQw3wu7cy12lVkzmyue+yr8f/EnJ7GVgWXxL
         IbnUU/N1JEs/3WIA7R0r6o/5va+14K82q4Z0Pkz4HzpRmjjPkLhIIsYHoiO0QRyo6Y7z
         Ay/A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533JVDwIoTfWsHhEY5VGqzQFjBHLBtx+mv+wgma/80vfgTsvSkYY
	JoNO7jScnkjZArQrHBssLLo=
X-Google-Smtp-Source: ABdhPJy4EuTN6INzcQp0P5UfspZjYJ+pgDcv5UCToqyJv6+QN3NUbZiv9pvEidZotXMh6MGYyQ8FUg==
X-Received: by 2002:a1f:eec8:: with SMTP id m191mr32912908vkh.47.1594018762439;
        Sun, 05 Jul 2020 23:59:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:7241:: with SMTP id n62ls592166vsc.2.gmail; Sun, 05 Jul
 2020 23:59:22 -0700 (PDT)
X-Received: by 2002:a67:c011:: with SMTP id v17mr37854302vsi.56.1594018761999;
        Sun, 05 Jul 2020 23:59:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1594018761; cv=none;
        d=google.com; s=arc-20160816;
        b=YaEjhozkyYqIu7aKz6eOgQ6IflUXNH/jOqadaeOPs+HCvuZIEkUWfS3tdE3xC2b1dA
         OPS9hys0AMOp1aOZjcES7WWEVZbB6CGixMvZLg6QZxtVvHly8n3qfc5X55eVC+7L6zGJ
         eovpuo4LTEhf4lNEm3YiY/Dn9dRyDDXFCUteoa3qT9AIgRrCeJndhPFI87o+Wg8dxDUz
         JrFynS4107T8jBsQ786iji77Gj9flic/bC1wOMJfpAv6+x5xgatMWVJYWpdtCAmQonFk
         MX+iHdsFsEr1otaTVqn40WEBE0BtIf9798dn6kUk8u0GqRBDAxXZG1zqMnQ/kj1fVIOZ
         sMFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=nPZqNQDBxsg4ytdwwt0Endr8/iEUUms3Rc4LlN2aaeY=;
        b=AI/+AwTh5akAkpw5ivE0TGM4QtJimQkMd0I10DFru5T1q+1m73VcEoE41+WK2d4xok
         dgScQ9HmV+p5eG5VRM/FUgTOC2Nd+HJr98u2OTckjzkCUZtSjKZ+UEXF0dfhcJlDKzL4
         3mHNjqNoxgtwRakF9EL2rO9zcHHmBf5/uaEsWoUHLQzEh+rIfj0lDWqA10OozikLy9wm
         fb/fbEC56j9G5igOQtwIlZWK18QzmQipCAvmRDr60azkNe+MHjVPZFFclIRcQUfbRJ/P
         G5Be9NqD/hX9RxnqaJRVKmbjsv4vKTzDW4YfaTA2vkRVg4q8vXhjqcswmbvKrA6IW1aF
         4mKw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=ZWXHNQeH;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id y197si1029420vky.3.2020.07.05.23.59.20
        for <kasan-dev@googlegroups.com>;
        Sun, 05 Jul 2020 23:59:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 9bf760c3df2f4e80aff10f4192957e77-20200706
X-UUID: 9bf760c3df2f4e80aff10f4192957e77-20200706
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 393689281; Mon, 06 Jul 2020 14:59:17 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 6 Jul 2020 14:59:13 +0800
Received: from [172.21.84.99] (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 6 Jul 2020 14:59:13 +0800
Message-ID: <1594018755.1706.3.camel@mtksdccf07>
Subject: Re: [PATCH v2] kasan: fix KASAN unit tests for tag-based KASAN
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, kasan-dev
	<kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, LKML
	<linux-kernel@vger.kernel.org>, Linux ARM
	<linux-arm-kernel@lists.infradead.org>, wsd_upstream
	<wsd_upstream@mediatek.com>, <linux-mediatek@lists.infradead.org>, "Andrey
 Konovalov" <andreyknvl@google.com>, Andrew Morton <akpm@linux-foundation.org>
Date: Mon, 6 Jul 2020 14:59:15 +0800
In-Reply-To: <CACT4Y+akZ5iu2ohQhRqiUd8zkew-NmrUPrA=xYtS1xxHWZ60Og@mail.gmail.com>
References: <20200706022150.20848-1-walter-zh.wu@mediatek.com>
	 <CACT4Y+akZ5iu2ohQhRqiUd8zkew-NmrUPrA=xYtS1xxHWZ60Og@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=ZWXHNQeH;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

On Mon, 2020-07-06 at 08:19 +0200, Dmitry Vyukov wrote:
> On Mon, Jul 6, 2020 at 4:21 AM Walter Wu <walter-zh.wu@mediatek.com> wrot=
e:
> >
> > We use tag-based KASAN, then KASAN unit tests don't detect out-of-bound=
s
> > memory access. They need to be fixed.
> >
> > With tag-based KASAN, the state of each 16 aligned bytes of memory is
> > encoded in one shadow byte and the shadow value is tag of pointer, so
> > we need to read next shadow byte, the shadow value is not equal to tag
> > value of pointer, so that tag-based KASAN will detect out-of-bounds
> > memory access.
> >
> > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > Cc: Dmitry Vyukov <dvyukov@google.com>
> > Cc: Alexander Potapenko <glider@google.com>
> > Cc: Matthias Brugger <matthias.bgg@gmail.com>
> > Cc: Andrey Konovalov <andreyknvl@google.com>
> > Cc: Andrew Morton <akpm@linux-foundation.org>
> > ---
> >
> > changes since v1:
> > - Reduce amount of non-compiled code.
> > - KUnit-KASAN Integration patchset are not merged yet. My patch should
> >   have conflict with it, if needed, we can continue to wait it.
> >
> > ---
> >
> >  lib/test_kasan.c | 81 ++++++++++++++++++++++++++++++++++++++----------
> >  1 file changed, 64 insertions(+), 17 deletions(-)
> >
> > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > index e3087d90e00d..660664439d52 100644
> > --- a/lib/test_kasan.c
> > +++ b/lib/test_kasan.c
> > @@ -40,7 +40,11 @@ static noinline void __init kmalloc_oob_right(void)
> >                 return;
> >         }
> >
> > -       ptr[size] =3D 'x';
> > +       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> > +               ptr[size] =3D 'x';
> > +       else
> > +               ptr[size + 5] =3D 'x';
> > +
>=20
> Hi Walter,
>=20
> Would if be possible to introduce something like:
>=20
> #define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : 8)
>=20

It is good suggestion. Thanks.

> and then add it throughout as
>=20
>         ptr[size + OOB_TAG_OFF] =3D 'x';
>=20
> ?
> The current version results in quite some amount of additional code
> that needs to be read, extended  and maintained in the future. So I am
> thinking if it's possible to minimize it somehow...
>=20

Ok, I will send next patch by your suggestion.

Thanks.

> >         kfree(ptr);
> >  }
> >
> > @@ -92,7 +96,11 @@ static noinline void __init kmalloc_pagealloc_oob_ri=
ght(void)
> >                 return;
> >         }
> >
> > -       ptr[size] =3D 0;
> > +       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> > +               ptr[size] =3D 0;
> > +       else
> > +               ptr[size + 6] =3D 0;
> > +
> >         kfree(ptr);
> >  }
> >
> > @@ -162,7 +170,11 @@ static noinline void __init kmalloc_oob_krealloc_m=
ore(void)
> >                 return;
> >         }
> >
> > -       ptr2[size2] =3D 'x';
> > +       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> > +               ptr2[size2] =3D 'x';
> > +       else
> > +               ptr2[size2 + 13] =3D 'x';
> > +
> >         kfree(ptr2);
> >  }
> >
> > @@ -180,7 +192,12 @@ static noinline void __init kmalloc_oob_krealloc_l=
ess(void)
> >                 kfree(ptr1);
> >                 return;
> >         }
> > -       ptr2[size2] =3D 'x';
> > +
> > +       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> > +               ptr2[size2] =3D 'x';
> > +       else
> > +               ptr2[size2 + 2] =3D 'x';
> > +
> >         kfree(ptr2);
> >  }
> >
> > @@ -216,7 +233,11 @@ static noinline void __init kmalloc_oob_memset_2(v=
oid)
> >                 return;
> >         }
> >
> > -       memset(ptr+7, 0, 2);
> > +       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> > +               memset(ptr+7, 0, 2);
> > +       else
> > +               memset(ptr+15, 0, 2);
> > +
> >         kfree(ptr);
> >  }
> >
> > @@ -232,7 +253,11 @@ static noinline void __init kmalloc_oob_memset_4(v=
oid)
> >                 return;
> >         }
> >
> > -       memset(ptr+5, 0, 4);
> > +       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> > +               memset(ptr+5, 0, 4);
> > +       else
> > +               memset(ptr+15, 0, 4);
> > +
> >         kfree(ptr);
> >  }
> >
> > @@ -249,7 +274,11 @@ static noinline void __init kmalloc_oob_memset_8(v=
oid)
> >                 return;
> >         }
> >
> > -       memset(ptr+1, 0, 8);
> > +       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> > +               memset(ptr+1, 0, 8);
> > +       else
> > +               memset(ptr+15, 0, 8);
> > +
> >         kfree(ptr);
> >  }
> >
> > @@ -265,7 +294,11 @@ static noinline void __init kmalloc_oob_memset_16(=
void)
> >                 return;
> >         }
> >
> > -       memset(ptr+1, 0, 16);
> > +       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> > +               memset(ptr+1, 0, 16);
> > +       else
> > +               memset(ptr+15, 0, 16);
> > +
> >         kfree(ptr);
> >  }
> >
> > @@ -281,7 +314,11 @@ static noinline void __init kmalloc_oob_in_memset(=
void)
> >                 return;
> >         }
> >
> > -       memset(ptr, 0, size+5);
> > +       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> > +               memset(ptr, 0, size+5);
> > +       else
> > +               memset(ptr, 0, size+7);
> > +
> >         kfree(ptr);
> >  }
> >
> > @@ -415,7 +452,11 @@ static noinline void __init kmem_cache_oob(void)
> >                 return;
> >         }
> >
> > -       *p =3D p[size];
> > +       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> > +               *p =3D p[size];
> > +       else
> > +               *p =3D p[size + 8];
> > +
> >         kmem_cache_free(cache, p);
> >         kmem_cache_destroy(cache);
> >  }
> > @@ -497,6 +538,7 @@ static noinline void __init copy_user_test(void)
> >         char __user *usermem;
> >         size_t size =3D 10;
> >         int unused;
> > +       size_t oob_size;
> >
> >         kmem =3D kmalloc(size, GFP_KERNEL);
> >         if (!kmem)
> > @@ -511,26 +553,31 @@ static noinline void __init copy_user_test(void)
> >                 return;
> >         }
> >
> > +       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> > +               oob_size =3D 1;
> > +       else
> > +               oob_size =3D 7;
> > +
> >         pr_info("out-of-bounds in copy_from_user()\n");
> > -       unused =3D copy_from_user(kmem, usermem, size + 1);
> > +       unused =3D copy_from_user(kmem, usermem, size + oob_size);
> >
> >         pr_info("out-of-bounds in copy_to_user()\n");
> > -       unused =3D copy_to_user(usermem, kmem, size + 1);
> > +       unused =3D copy_to_user(usermem, kmem, size + oob_size);
> >
> >         pr_info("out-of-bounds in __copy_from_user()\n");
> > -       unused =3D __copy_from_user(kmem, usermem, size + 1);
> > +       unused =3D __copy_from_user(kmem, usermem, size + oob_size);
> >
> >         pr_info("out-of-bounds in __copy_to_user()\n");
> > -       unused =3D __copy_to_user(usermem, kmem, size + 1);
> > +       unused =3D __copy_to_user(usermem, kmem, size + oob_size);
> >
> >         pr_info("out-of-bounds in __copy_from_user_inatomic()\n");
> > -       unused =3D __copy_from_user_inatomic(kmem, usermem, size + 1);
> > +       unused =3D __copy_from_user_inatomic(kmem, usermem, size + oob_=
size);
> >
> >         pr_info("out-of-bounds in __copy_to_user_inatomic()\n");
> > -       unused =3D __copy_to_user_inatomic(usermem, kmem, size + 1);
> > +       unused =3D __copy_to_user_inatomic(usermem, kmem, size + oob_si=
ze);
> >
> >         pr_info("out-of-bounds in strncpy_from_user()\n");
> > -       unused =3D strncpy_from_user(kmem, usermem, size + 1);
> > +       unused =3D strncpy_from_user(kmem, usermem, size + oob_size);
> >
> >         vm_munmap((unsigned long)usermem, PAGE_SIZE);
> >         kfree(kmem);
> > --
> > 2.18.0
> >
> > --
> > You received this message because you are subscribed to the Google Grou=
ps "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send =
an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://urldefense.com/v3/__ht=
tps://groups.google.com/d/msgid/kasan-dev/20200706022150.20848-1-walter-zh.=
wu*40mediatek.com__;JQ!!CTRNKA9wMg0ARbw!zqGS_g-oLI7o6850GjV_P7YQPr8SufdeC8f=
bnt27o4WtvhX5PZ8-eZ6BWyF3bwm7Tizipw$ .

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1594018755.1706.3.camel%40mtksdccf07.
