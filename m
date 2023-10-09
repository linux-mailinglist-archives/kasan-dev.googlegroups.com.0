Return-Path: <kasan-dev+bncBDW2JDUY5AORBJNPSGUQMGQEO47VZ2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 28E1D7BEAC5
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Oct 2023 21:42:31 +0200 (CEST)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-57ed6d8fa9asf5425255eaf.3
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Oct 2023 12:42:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696880549; cv=pass;
        d=google.com; s=arc-20160816;
        b=pfAaro8QElMevciZqhHeSvmBnpDjwkokiJE4CMvT3bGyUSslgkdV8nCgZ76NMndjFN
         Ek81ubfIvj8pO1rD2B2FJaFr9toaOmPjLEziu/xzKaGOBsVa0na7MeuY/FtcCLH6+sud
         No59m08kcPdIrnziQvlNrJKUUI1MnRmQsXgqBJ6o6afoue1pKtOkLvMKRv7rHrd3qUT/
         tIFndiymm0W4Ig8B1NjgHDxsNa8PgA20uZHdeDMQpfbP68acVat18icp4cv/4IIIsHdm
         tZZW9kU47IR0fI1z0nZZD8ZvkshwcyaJTDYZPV1zKKCyctF8FbUx0pTocjOukqVSlbnZ
         P8/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=RM/foP0g5FolIUQJMiaBckSK9dCCbUf7Ojp1uqxicHA=;
        fh=CcGKEEIG2DEPxAGxi6TmiJpq8E/yJNefwvJr/FBbJdM=;
        b=TFm9UR8BDOK/aJmnw2kceBogWAyvjL7wqeg3/R0NeGRMmNAeZmTsGlkiTYDLznvt3N
         c84xcpvpCjVJt1DJ5/peWuAIL7tce+GsWOu4v78jekX9Ej6KutJWPDoxwF+1iqdRYrNd
         Llglig+/F0nSxq98+wkevRSu7gX81zuFPnxB0DjcZ3pcbITrY+surCS9/FmAE0E263uc
         wKeKGxjyx+BY/LRvq5oh5HbudY0/sIct6gcyDRUe7RbdnQN773dxWaGNgpei2frfwVfA
         AoLhFgd59xAhsnB5f+Xc5PZKjsgWoWmmIYnnKFUNWzh73goFPuRshBb+IInBOYpnRGdN
         pGsg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=DstjMFy7;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696880549; x=1697485349; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=RM/foP0g5FolIUQJMiaBckSK9dCCbUf7Ojp1uqxicHA=;
        b=t32TybTB5c7VoF/GKcf4Z1seZ7u+LIin8ieUusxATst6stOXBwwjuEgUT0sMJGMU+L
         gy51XPo6ynjJWn2/07ub2NmCEpk000gQEahAa5Cy9iBilGwqTrlrYiRsl9OnwwWuWFAq
         Iq8ewiM8+w53iwq4oKSrXcmiAJ3LN+trqYGFPo2Nm4utu2RkPBi5I8dC8gDyy55S25XW
         VJQ7nHpaFNai/f+vd2xAA64F5GvzrVl7/i1rp6kDyzDfMHhlpIHLcHwrhTezbrbIEuYV
         rQVw0pQojcBHNUZAa3cC6roqK7U9ck85qdsCc7dwy3UQ3p8kiV/Xj2t99LopY8vPgCNy
         gxZA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1696880549; x=1697485349; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=RM/foP0g5FolIUQJMiaBckSK9dCCbUf7Ojp1uqxicHA=;
        b=FiDX3wnTKflSl1ieo7dynHGMw1Fih9Bw1jNM5CnD0I95+pm2oFIMLFWp8Ycwdt3oAA
         JE84zchIS8xlJ1ci1lFfdm9HPCIoAdpNl4jqjLnPZcnBxhBWqHSRTGIA6lvxATdT+7GF
         YGdB7nHW+inAa9j3Ws+ZH3wdgfKmEwtghLpuT1Eg/ZxzxgyRBFgh9kZNzo+xA/nLoNN2
         Kp9Mwi3rl4H2jMryrxZ2bZDMRz95utDJfCFWHB7Kah8W2BKbfR8doIFLTMRytIQ6GiPL
         NAXno/xmW+2MHnmDhuWp8KV6IBnnQP55deUQuRbSGuqhWV3tZxgEhxkm5IrsqVsQFKqU
         oDwQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696880549; x=1697485349;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=RM/foP0g5FolIUQJMiaBckSK9dCCbUf7Ojp1uqxicHA=;
        b=wrfyd5pObbDpLHjrjJk82pAljCTV/IwEmVK5DWgqUxdXUf7PESgc5N6dJgmUDs1by7
         /ta9mLSZ8kGHKdc+fVjt7eMook5QC7he1vI144KDAgc3VG10YoVT0ggI5R/p1EJneLFp
         mY9uX/u1CCXgKnK1IHpyLlvsXS1REuf8fuuDp9PzmxS0NMFayW5vEYkRTJcA1gcbqVys
         Dg/f+h3sMePhNdFixh9Rvx5FPO3/v+cjA1gOIq/yE5PrVnM8w+EF3IFafuPdgDraAPP1
         F9k93wyjvD71wEqBwf8UDdAzlc0DIPAtzf1glkvm6jk4UJVl9Yj50F3qJ7IVhsqflxO6
         5nOg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yw8JES1FaLVfl6fTEONiq/zYqvvVZrd31Sh05uoYfKf6Cek6KQt
	pC1a53q4WH4osz3C72ulE2I=
X-Google-Smtp-Source: AGHT+IG2eqXaM1EvIxRkYiC2GlN5YQrPuIjDu3HStuJMdZolyxFdLCQuVY8ioWbDoTxMJNYwd47IEA==
X-Received: by 2002:a4a:301c:0:b0:56c:dce3:ce89 with SMTP id q28-20020a4a301c000000b0056cdce3ce89mr14269243oof.5.1696880549705;
        Mon, 09 Oct 2023 12:42:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:4f87:0:b0:57b:5446:2f55 with SMTP id c129-20020a4a4f87000000b0057b54462f55ls3495305oob.2.-pod-prod-06-us;
 Mon, 09 Oct 2023 12:42:29 -0700 (PDT)
X-Received: by 2002:a05:6830:4c6:b0:6be:e447:dbd with SMTP id s6-20020a05683004c600b006bee4470dbdmr14457383otd.22.1696880548933;
        Mon, 09 Oct 2023 12:42:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696880548; cv=none;
        d=google.com; s=arc-20160816;
        b=wl/p5qor+BPfRxjxf97vwgSA31Rt2Gg0e3lQ6e1el8mSoEDkFmPq+kVjbvn6ziF41g
         /BZXDX+g8KuZGojee7cu+oFCOy5sJ+SrLz+dMbYPT+KN0P/ns7IXxO48ZGj+VTD2PKmd
         5xpbqAFkebD2ErHDb/N9ajdMG0tscRNBWcrP7k6kdO9piDIAAJ4njGj6fOVOGd9/GkNU
         vBkQzJf1iDMtkLQ2Rj4x+vgAAN24GyoX7FwQY3fM3FMREAlgi40NM9NF+DOOUOtRGk0T
         0ets3KX6dg6Zo5pAT4j1iNscyr2Ny9ihXhiaknqPw1BT1Lyfaz3+4JzUfE50GBjKytA9
         2MLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=cPDCWjeLigUTOz7mgyt00FMkqMkRL1/1wVrDbyf+7ZI=;
        fh=CcGKEEIG2DEPxAGxi6TmiJpq8E/yJNefwvJr/FBbJdM=;
        b=hzSCtNj5uICdp08rZ+ngDXXixShcWP6wdueVd8y7tJ6C/6B5IRvSbic29gdBEmfSV8
         LmIWQsJ2TOi3jSw92ILYlxUgtjmdsRUhaHkTIEJctanWvAjXIk4t4z5AQUCSD567NqTH
         MuR/GaYB9sYfsaDK3G2RcsTANQfxoGVTgDecrCEqeMXJliPJn5wIki/5vzUnt3CLZBJ8
         +y96r6nh1yUd/D4PnUomys2QkSfMfb0cbBCoT65UruI05asdBlNWpk8UXvOUa+oFQD70
         U73Jaa9V62nmtV4Xh6gdxB4XDS0j7n7RuverN+wszobV8VrGEeXmoUvfxdBtYieU4TN/
         GMwQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=DstjMFy7;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x52f.google.com (mail-pg1-x52f.google.com. [2607:f8b0:4864:20::52f])
        by gmr-mx.google.com with ESMTPS id dy12-20020a056830210c00b006c649087cf8si942466otb.4.2023.10.09.12.42.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Oct 2023 12:42:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52f as permitted sender) client-ip=2607:f8b0:4864:20::52f;
Received: by mail-pg1-x52f.google.com with SMTP id 41be03b00d2f7-578d0d94986so3589504a12.2
        for <kasan-dev@googlegroups.com>; Mon, 09 Oct 2023 12:42:28 -0700 (PDT)
X-Received: by 2002:a17:90b:124c:b0:279:98f6:deac with SMTP id
 gx12-20020a17090b124c00b0027998f6deacmr15079471pjb.20.1696880548133; Mon, 09
 Oct 2023 12:42:28 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1696605143.git.andreyknvl@google.com> <6fad6661e72c407450ae4b385c71bc4a7e1579cd.1696605143.git.andreyknvl@google.com>
 <CANpmjNOp0yq2vQmSmTim=AF7bm9XdStbaQE9B=wVwpKkO_y6tQ@mail.gmail.com>
In-Reply-To: <CANpmjNOp0yq2vQmSmTim=AF7bm9XdStbaQE9B=wVwpKkO_y6tQ@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 9 Oct 2023 21:42:16 +0200
Message-ID: <CA+fCnZfES0OV16s3i3B-p2fGYhRa-Z3wQ5QzJbrCmGnfBgzC5w@mail.gmail.com>
Subject: Re: [PATCH 4/5] kasan: fix and update KUNIT_EXPECT_KASAN_FAIL comment
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>, 
	kernel test robot <lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=DstjMFy7;       spf=pass
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

On Mon, Oct 9, 2023 at 10:48=E2=80=AFAM Marco Elver <elver@google.com> wrot=
e:
>
> On Fri, 6 Oct 2023 at 17:18, <andrey.konovalov@linux.dev> wrote:
> >
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Update the comment for KUNIT_EXPECT_KASAN_FAIL to describe the paramete=
rs
> > this macro accepts.
> >
> > Also drop the mention of the "kasan_status" KUnit resource, as it no
> > longer exists.
> >
> > Reported-by: kernel test robot <lkp@intel.com>
> > Closes: https://lore.kernel.org/oe-kbuild-all/202308171757.7V5YUcje-lkp=
@intel.com/
>
> "Closes" isn't a valid tag? Reported-by + Link should be enough to attrib=
ute.

I believe it is: the robot asks to use it, see the link. (I think this
tag is also used by syzbot btw.)

> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
> Reviewed-by: Marco Elver <elver@google.com>

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZfES0OV16s3i3B-p2fGYhRa-Z3wQ5QzJbrCmGnfBgzC5w%40mail.gmai=
l.com.
