Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBQ665W2QMGQEZFZ7SIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id E82F49507CE
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Aug 2024 16:35:49 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-53214baf2aasf1244217e87.2
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Aug 2024 07:35:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723559749; cv=pass;
        d=google.com; s=arc-20160816;
        b=biS6FnfcaFztrW9JEFQtSjj0/y9J5ZOrQ7x/l2+IBfIU2OvKVx6edO6/dDvs9wfAjR
         gmJFI4QX8XsStvs9W2x0h7n6IBEvld74aUXcxSTDdT5XDSQcwcfTrohv1qKgDO3U+PSY
         IAWiIlerBdetHgvJY2137hpftO6y7i5FcUarsus58c5yWLGEN2KsfjO8R6x5Qurc8GmO
         Z+fx6KHQdDn0dM78cwX87sIBo56j1jtYf3LiIFv3f9MfdCRAq/y5RDxYfgFaIERiV8ra
         NLDhbYVl2T6q4Qi0ra0E4qSe6ffryDrXl/BgksdJJ2lgRefUB7OQnns28oDSodCspBMh
         64YA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hym6hqV4SSXoMkeGLbo7S77r7U56jtrLZlKb0BY2h0M=;
        fh=6sJxgyo1dKxgz3b2Bbp7llnlsdBHLAv0Y83MN1IG7Xo=;
        b=odklMw2qlgNb7OPxTkFmvupjZEDAy6PmwbGTdPdoOI1pm/l0Hk4rsy6WH5vXW3l7rp
         ejkC2UcxeDmdnULXf1yG+nBXgOaSY30kztD71LAjGA2ypmCF83mUQtoQh2P5OgpgL1xl
         60WYnzudyWZXRXoU0pmye2mgYtvufmBQLDKwo49GubtQY+kkQnwRTozUfNOxueJjofiO
         f9GUzP13rS1w3ssNHZWZ51fGVQbh/h9dszMHWw6OPkal7zfH4++lyIHO9rZwZKoJ8PpT
         KKxWhD8JObugLoNAEKOHl1XA3UT5Zsa16MleCJDjOOSmC+XYy0vxm+2QlEuJ/jtPGHb6
         cDeQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MJjng31k;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::536 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723559749; x=1724164549; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=hym6hqV4SSXoMkeGLbo7S77r7U56jtrLZlKb0BY2h0M=;
        b=duxk6EWHrxL1uyK8pULkNxKu37/3f917mFtFSX+WR9c4gYxETsIxpzO/scKO59hddo
         jq6yPTmJDhgbj4C9BHJuFAEpuuUtDCaYMaB3VFOCLkKhz9z3XrSpFocCKL/5kPVobTxl
         igV7jmYvbZ15BgE5aIQyhGnODDkMBsdhaFJnCJY2F/Cvhf7o96NuWiGwh7OYZ4v9kK/f
         FYiImHFKEG2pYuDDza3PxVWSnYWCRIp3zfSpVZ/SYfavfAxuQBJahBddtTfAJeJSv5q6
         zOvIy6WK/9NHrfPQP75y790ozBAQNJ/lHXZS5qCUEEcrzF1/irmmH9G6B3eF76mUuV+e
         T3qA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723559749; x=1724164549;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=hym6hqV4SSXoMkeGLbo7S77r7U56jtrLZlKb0BY2h0M=;
        b=QMx+u1GGSL3HCe5E3308VYSffZv1NWVbTBHNqOj9Etcu69G9sS3+AFKRN6d+yzXiO/
         NVh9po/FMeFq1548UMAosXm1N/TTIjxQqQuL9Ddj7wuFBWfkgbkD3xXZz9WW7fNAzRzU
         zEkFL6ypzShKUOE8uta25mRRGn5eS/IxPDeF8WjKJaZQGc3qdqNAlh6TnHvtgnTjxtJP
         P62TkpZhRzC5424sbVZ1y78T8jQ3Lbtu0qsrssQevhCag1BQf/b5FpzHYFGls9RucDZJ
         LJwMgUdJAvQjhouAC/xBsDN2QZWRRnXqpa0119DXZW71kFuWYjC3ccdHh3+08sVdze1E
         Z2JQ==
X-Forwarded-Encrypted: i=2; AJvYcCWbpQqew08FiAsg+DovQnNnEK/1roznrqSEeZF0rPlcCcDdSziUK07jH+1yrux0MQOM97laVFfBhBL2itO3fmWBOgGMaV0MCQ==
X-Gm-Message-State: AOJu0YzD9/3qwcgTVE9o9Q2c+XVz0GRoWaITFgsUfrleZtdjdGmf3Lwk
	fyPi8FsXQX9716U5REew6pBuU7wBr3f7wKOwEhCnv46y2mdvyBGP
X-Google-Smtp-Source: AGHT+IGkg62bLRRW/mrbbJuZb0w3CAAgZMW5h+wpkRO27qHjrruGgiuMgjpe/St0nr37Tv5hsCGk8A==
X-Received: by 2002:a05:6512:12cc:b0:52b:be6b:d16a with SMTP id 2adb3069b0e04-532136599femr3185777e87.31.1723559747939;
        Tue, 13 Aug 2024 07:35:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b90:b0:52f:d1b7:329a with SMTP id
 2adb3069b0e04-530e3a0be73ls3492202e87.1.-pod-prod-05-eu; Tue, 13 Aug 2024
 07:35:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUeSv9tnZVb4ljRS7Y7mbX0h9bfMZOWMNJj0FzGA7eFo1Q1aqEKrx+0R3eRxRAKs3C5Zy4LcAKbizLtjLAEEup+lMygEPUznO/pdQ==
X-Received: by 2002:a05:6512:23a4:b0:529:b718:8d00 with SMTP id 2adb3069b0e04-532136479b1mr3159624e87.8.1723559745654;
        Tue, 13 Aug 2024 07:35:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723559745; cv=none;
        d=google.com; s=arc-20160816;
        b=txtSvKib4xbNxOgJExrSavAmAjbtDjzTKDT10STFRGcBw4wFWzT74nZwogC6rkRvh9
         736atPKKBdSrE8jyDlTswe6wG2/YCzpsavCbSibinYh7p3pvGY8tolVPZjARQT9EkaIk
         yxuNIvygtllZ+UEFZo7b4PkDiZLdyKGA0fEx3HLgvwwk6e8rx0fCTB4+Tt9HLcyc2lCs
         GDrWkBNr9uikksvWklCu50ZutvgyH7Ko/Peq9E41lNc83lQXmNkCSBi8TzE+WjhBf1pN
         v2g3rHf/JCti8+9fl9fvLv2z3Zl60njzx8ciORXOmX704+kcvrf66EpMYlCtXZ/DQDC5
         UlLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=jHkUUb+Bb79GP/2rKFx5/OBmUophNr82XKuyu6ufGDk=;
        fh=YvldyawqGneLeU4c2dOw0Q5IdPIgYI2fwt0ARAUqaoU=;
        b=HdSFqPs8m3nbO8Kuaw9J5Wc/X0diy3H0ujHTNFQm6ovLxImQiseI/Nkn/QvKY7zTbw
         KbDgOFwC+xnyL686RVeBFuFS25RLR/+CDcaUSFmbeJ3vsAx5Yfge45XtiMpK7/Oiu0gT
         wR/oHLQAzSBn+uPHA8Pe9zouZSgfD7i25PRK0PStPnVjZ/OlgJ+sAhSpWiVRgf/1+Stw
         qRJvi4akLdfgSABbLC5y6wftpR9UXdWoIaJOYVd12qgzXNq3Quno6eA7rmhA8iDx6WY+
         sj1FrUvFrZPITaP1+U+m5hZYWhNMxs/8x0VzX7OPmcQuXyKwaOZn288ylq1hYFwLNDUS
         xHHg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MJjng31k;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::536 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x536.google.com (mail-ed1-x536.google.com. [2a00:1450:4864:20::536])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-53200e91898si148986e87.1.2024.08.13.07.35.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Aug 2024 07:35:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::536 as permitted sender) client-ip=2a00:1450:4864:20::536;
Received: by mail-ed1-x536.google.com with SMTP id 4fb4d7f45d1cf-5a28b61b880so7022a12.1
        for <kasan-dev@googlegroups.com>; Tue, 13 Aug 2024 07:35:45 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXr05NjD37f+52898eriDZgwDkLM0RNBvy0PKGjZ1izzdvexuv4rjXO+XPFg8jH0VXzSNZOBgKtD0pNOtHQUbebpkH8fgf8571pkQ==
X-Received: by 2002:a05:6402:13d0:b0:5bd:3fff:7196 with SMTP id
 4fb4d7f45d1cf-5bd476d59e2mr100042a12.6.1723559744140; Tue, 13 Aug 2024
 07:35:44 -0700 (PDT)
MIME-Version: 1.0
References: <20240809-kasan-tsbrcu-v8-0-aef4593f9532@google.com>
 <20240809-kasan-tsbrcu-v8-2-aef4593f9532@google.com> <vltpi3jesch5tgwutyot7xkggkl3pyem7eqbzobx4ptqkiyr47@vpbo2bgdtldm>
In-Reply-To: <vltpi3jesch5tgwutyot7xkggkl3pyem7eqbzobx4ptqkiyr47@vpbo2bgdtldm>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 13 Aug 2024 16:35:07 +0200
Message-ID: <CAG48ez2DUgxh3f4N=i60TfHBSTbh2HPMbA8DcBo2g7HSepnzzg@mail.gmail.com>
Subject: Re: [PATCH v8 2/2] slub: Introduce CONFIG_SLUB_RCU_DEBUG
To: Shinichiro Kawasaki <shinichiro.kawasaki@wdc.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	Marco Elver <elver@google.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, "linux-mm@kvack.org" <linux-mm@kvack.org>, 
	David Sterba <dsterba@suse.cz>, 
	"syzbot+263726e59eab6b442723@syzkaller.appspotmail.com" <syzbot+263726e59eab6b442723@syzkaller.appspotmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=MJjng31k;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::536 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

Hi!

On Tue, Aug 13, 2024 at 11:03=E2=80=AFAM Shinichiro Kawasaki
<shinichiro.kawasaki@wdc.com> wrote:
> Hello Jann, let me ask a question about this patch. When I tested the
> next-20240808 kernel which includes this patch, I observed that
> slab_free_after_rcu_debug() reports many WARNs. Please find my question i=
n line.

Thanks for testing linux-next.

> On Aug 09, 2024 / 17:36, Jann Horn wrote:
[...]
> > +#ifdef CONFIG_SLUB_RCU_DEBUG
> > +static void slab_free_after_rcu_debug(struct rcu_head *rcu_head)
> > +{
> > +     struct rcu_delayed_free *delayed_free =3D
> > +                     container_of(rcu_head, struct rcu_delayed_free, h=
ead);
> > +     void *object =3D delayed_free->object;
> > +     struct slab *slab =3D virt_to_slab(object);
> > +     struct kmem_cache *s;
> > +
> > +     kfree(delayed_free);
> > +
> > +     if (WARN_ON(is_kfence_address(object)))
> > +             return;
>
> With the kernel configs above, I see the many WARNs are reported here.
> When SLUB_RCU_DEBUG is enabled, should I disable KFENCE?

These features are supposed to be compatible.

In the version you tested
(https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next-history.gi=
t/tree/mm/slub.c?h=3Dnext-20240808#n4550),
I made a mistake and wrote "if (WARN_ON(is_kfence_address(rcu_head)))"
instead of "if (WARN_ON(is_kfence_address(object)))". That issue was
fixed in v6 of the series after syzbot and the Intel test bot ran into
the same issue.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG48ez2DUgxh3f4N%3Di60TfHBSTbh2HPMbA8DcBo2g7HSepnzzg%40mail.gmai=
l.com.
