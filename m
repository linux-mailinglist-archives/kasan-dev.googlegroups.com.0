Return-Path: <kasan-dev+bncBDW2JDUY5AORBVOYQ6UAMGQEI6MDOKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5FE3579EFD4
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 19:07:35 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-1c0cfc2b995sf90980265ad.2
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 10:07:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694624854; cv=pass;
        d=google.com; s=arc-20160816;
        b=X2npQhMLzChgtWoKl+zdFu3FtgBbKZYOe+XYuw17uaFYd2TmO8xwsyQIPhVtyaxeQw
         O8KYnX4ZKGUrgClJue/pwjC6Q2y7lIz8QdqrbtmbZaQewXoRU0l1ecR/efyY3Am3FTAi
         A0ciyglUxBsPuy6vmx1FjtPPI6EHF+4ZB9C3FWZ572v53b5W5QEHaWpE24LiodIy/8Wg
         KgCSuWC7W9R7znWlkW1yxpCVr+UVzHn3pgfq0KLyYN4UYnEMOOVAWFEVjJzeXDBcUzS0
         T5OxZq/4SVNeZTAJ+Htzpi+yAQQfo7n7OOreNCoJkw7U/F8M0a4ddaIJlXHTLetDjUm8
         jyZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=g0r721rqihZhRPfER/RDQIT4wPpXHzJKTOIffuRJf80=;
        fh=WjHOb0y/FYtZmaO/E8L4JCrnxMyERwu35tR6GaUdiBo=;
        b=GGRG9iskIumSqTjdFqz2BQZOytKzpaHQnY+vFqMFCOKi1or1NB7KzrlXujWguoRSD0
         4EV2pjNtMYFXxHzUC3U1h6KO+3n6pjrbUhpLkcIPxvm4PhSXLVGGXmMTdk4D9RKRtHI6
         rRNDahcrMraDyxeHerqVZy8Gn/r/ilbSwnceKa3X68UYpwH3NeN7b3YXjH9+cUtsLlDQ
         Khmxg6GZ8dVQqXSjoYdjnhyBSPyTunOKAytZJZnrWFDVzVDELW5azaOiius/8MvhIuuT
         VEQhWG/cY9ccjBfiPPwUs/zKN0WBD5ovNZLkRZ1yW+C/7TD/HWqFihELIHCMXCXFsFmF
         J4BA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=B4J6frwU;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694624854; x=1695229654; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=g0r721rqihZhRPfER/RDQIT4wPpXHzJKTOIffuRJf80=;
        b=V5d8BhwT1Q1pvic52z6QxxTYIh7ld5Rp67GtoRi3n6HJHhdgL4s+Y0+UrnVHjJfyel
         MvILSQFcbR651MuIR4vboydl8krKV9dVOzN+fTAwiNl3KpcYl///3l+gLFcZLEJUaq7X
         5ioS+deU4jT8cpQ4znVshmb4sY5UAU8K8Z7uRzhURMISzJdXZoqRoR27atVUGhoxRRu2
         Bbnjl9iwvM6qDohitIeoIXN5RsVLFwzUap0s5VKn6V6N5Li1OAwQUHhn7NCvrbQXSFCB
         QmVvP+P8wOrKoJt43fnm3ddtI0PcGK2nC1bby/Z4E/81R0qf+KwWZLL6peZ+bBeu189w
         pObw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1694624854; x=1695229654; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=g0r721rqihZhRPfER/RDQIT4wPpXHzJKTOIffuRJf80=;
        b=k3H4zOXzPHCSCwodC0xH8ryJSVWUAYyI/u/DtAq1TpZV1Le2pVAxgL+3KvjuO65Zfw
         UYF7dkzijewhjWPIVgWlJN79kyR98Rjq8uT6kKiBJ4f1KLZ477qqcDhxUHsNO/CtPuu1
         rIe6mBnHacOXBWLD195biLRn+f6vdRjCDKDF2zsGhJFSSNp2qIkjUO6eqxxsjw6FPOjJ
         1c/k0y0R4GukWzw2oSa/PWnUl/ebXrXFe+mgil35TcxgzdbcMh0xNqT4cbNqGcQXb2YF
         7LdcU8yd73vVjgslN3jxktgFw8fB4yzm9D7xCTO1INagXstQY0y4R0JKAs3Hq5RziqHA
         XFdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694624854; x=1695229654;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=g0r721rqihZhRPfER/RDQIT4wPpXHzJKTOIffuRJf80=;
        b=GHaR+rg7J07k/pmE/5THI6zPHHkH3XRYSHMcvGNQzimeSwaT7+NzT/tDH7LN1A/JIL
         YwWPz18uKFZSpjMWUx63PRQNuOhOnNo2M4doDvW3L2LtsYMq7DpdzwEzmw9Z45DsUn+L
         CC3tC+VCzN0kjmrZkhSUYvMfdaT1yfO5nypXjf05SDFU6WUb3Yj+HnpJEGcutR+f9Sow
         alW+eENVIoTdZUZ2fTS7p4dsrPmzX2wsB3svLy2XuDHjvQ1jZEmbhtVXqvanEJs0mubI
         acejK9SSt8sP9NWnFuEJkYcY7OdJkkaClNmWkNJSM7/FXxCVnPub5+DqI4E6nCcTdNev
         bxfw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yz6XzJMCdsW2PZFU5ibfCJ86IvqO9TkhGph+w2FERARakWNXtoS
	OB65alrVRjyVpaJ66dYvkgU=
X-Google-Smtp-Source: AGHT+IGTmguK+ielvfRD+KobJSU4OwAXcNS+uvu8dCDKcU1ksQghx9bIxVaKcLqyLETAuSpa3OXiKQ==
X-Received: by 2002:a17:902:968f:b0:1bb:c64f:9a5e with SMTP id n15-20020a170902968f00b001bbc64f9a5emr3072629plp.5.1694624853627;
        Wed, 13 Sep 2023 10:07:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:654f:b0:1b8:a58e:6f4a with SMTP id
 d15-20020a170902654f00b001b8a58e6f4als4179733pln.0.-pod-prod-02-us; Wed, 13
 Sep 2023 10:07:32 -0700 (PDT)
X-Received: by 2002:a17:903:496:b0:1c4:16f:cc3e with SMTP id jj22-20020a170903049600b001c4016fcc3emr134422plb.35.1694624852679;
        Wed, 13 Sep 2023 10:07:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694624852; cv=none;
        d=google.com; s=arc-20160816;
        b=OMSlgtUK3JrZCfEGGiOZTsH25094b7KlOt+NGqciOM3wBL8O6j7HSEdrzTlagcpdwT
         70mCXB/B0v0jqShMwwnASHCh9i7Y2VZqJxau0nfKZj5fKs1Rqry9ISZ3KDx1ruvPgqiu
         c06hOQwswN+wT3Zt3ZEj6J+1NH+2HUu0Fgy8/77lCb5UOiXKSq9MOPqIwUMQ2vfo8peV
         tV/qz5SSHDf6bYh00T6exCiLloXK2Be19ZtaEzbv4VKqz1jiMumfA4bRv5FY3zbudTd6
         /cQztu5joWU3f6bhiAKrsO1UMr4uCUI1aMTlVoGCvsSFWNojgk2/wtPWslbZM9EXQHuZ
         BVhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=iAHlwDQj5aLs+kNJzI19rDW68TVeu+jwDvk+z6Yfntc=;
        fh=WjHOb0y/FYtZmaO/E8L4JCrnxMyERwu35tR6GaUdiBo=;
        b=JDDHnj94d5I2+ZpCdDJ+Em3aFu8vMU1M9b6kJwBMstGUpFrN0vYTPsmAnoNPJYqk8K
         cBfbb9Kp3cBLdpKDMrAHG4b5ChU1wUdAxGyXODOs1/WA5Nynvg/aw/e6OLtQb/SDY4La
         ScV04Chlyf0Ps5KECiNA6D2o2xj/q3dwy8da4AxbbbmsxRRogohHaV7Fh+zQ4LJVNOeH
         AdGXDzYq1Ce+atz+pVnNnzOcf3xU8jg4TcB5MUdAcg2DhB6nixMOhYsxIhjYkrRdPihy
         UsL/lraiqGiZENMyT8TECalqB4lOiho2MWseQFRyqJe6pqBg/SZbtE+MNTPE/eyLepNJ
         r2Xw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=B4J6frwU;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1035.google.com (mail-pj1-x1035.google.com. [2607:f8b0:4864:20::1035])
        by gmr-mx.google.com with ESMTPS id kz6-20020a170902f9c600b001c1f4ebc2bbsi1243899plb.6.2023.09.13.10.07.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Sep 2023 10:07:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1035 as permitted sender) client-ip=2607:f8b0:4864:20::1035;
Received: by mail-pj1-x1035.google.com with SMTP id 98e67ed59e1d1-27405bafa2eso44791a91.2
        for <kasan-dev@googlegroups.com>; Wed, 13 Sep 2023 10:07:32 -0700 (PDT)
X-Received: by 2002:a17:90a:887:b0:268:37b:a10e with SMTP id
 v7-20020a17090a088700b00268037ba10emr2692968pjc.11.1694624852255; Wed, 13 Sep
 2023 10:07:32 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1693328501.git.andreyknvl@google.com> <89c2f64120a7dd6b2255a9a281603359a50cf6f7.1693328501.git.andreyknvl@google.com>
 <CAG_fn=WsYH8iwHCGsoBRL9BRM-uzKJ3+RDgrB5DEGVJKLPagVw@mail.gmail.com>
In-Reply-To: <CAG_fn=WsYH8iwHCGsoBRL9BRM-uzKJ3+RDgrB5DEGVJKLPagVw@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 13 Sep 2023 19:07:21 +0200
Message-ID: <CA+fCnZftKPJ7zDWmPRjxYXQK91DX2eEw0nDNtYW856399v__Hg@mail.gmail.com>
Subject: Re: [PATCH 05/15] stackdepot: use fixed-sized slots for stack records
To: Alexander Potapenko <glider@google.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=B4J6frwU;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1035
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

On Wed, Aug 30, 2023 at 10:22=E2=80=AFAM Alexander Potapenko <glider@google=
.com> wrote:
>
> On Tue, Aug 29, 2023 at 7:11=E2=80=AFPM <andrey.konovalov@linux.dev> wrot=
e:
> >
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Instead of storing stack records in stack depot pools one right after
> > another, use 32-frame-sized slots.
>
> I am slightly concerned about the KMSAN use case here, which defines
> KMSAN_STACK_DEPTH to 64.

Hm, indeed. KASAN also defines the depth to 64 actually.

I think it's reasonable to change the default value to 64 to cover all
the existing users. And whoever wants to save up on memory can change
the Kconfig parameter (I'll add one as you suggested).

> I don't have a comprehensive stack depth breakdown, but a quick poking
> around syzkaller.appspot.com shows several cases where the stacks are
> actually longer than 32 frames.

Whichever value we choose, some of stack traces will not fit
unfortunately. But yeah, 64 seems to be a more reasonable value.

> Can you add a config parameter for the stack depth instead of
> mandating 32 frames everywhere?

Sure, will do in v2.

> As a side note, kmsan_internal_chain_origin()
> (https://elixir.bootlin.com/linux/latest/source/mm/kmsan/core.c#L214)
> creates small 3-frame records in the stack depot to link two stacks
> together, which will add unnecessary stackdepot pressure.
> But this can be fixed by storing both the new stack trace and the link
> to the old stack trace in the same record.

Do you mean this can be fixed in KMSAN? Or do you mean some kind of an
extension to the stack depot interface?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZftKPJ7zDWmPRjxYXQK91DX2eEw0nDNtYW856399v__Hg%40mail.gmai=
l.com.
