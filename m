Return-Path: <kasan-dev+bncBD52JJ7JXILRBQMWRSJQMGQEJQEYBXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id EEC7850C09D
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Apr 2022 22:08:34 +0200 (CEST)
Received: by mail-pg1-x539.google.com with SMTP id z18-20020a631912000000b003a392265b64sf5594007pgl.2
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Apr 2022 13:08:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650658113; cv=pass;
        d=google.com; s=arc-20160816;
        b=OFyrXtelTTnBz2xOZ9y1Jf3+fNBfDvbvQ3DSg9O5Z3lxrDSWKnlTi1ay9uRlH+/f1H
         BbD/kOLHXPI78Mgo93D4XwDNhrtB8qocNM8j3InupUuWxZNV4eX+BLRO5Pc9CoNKM38P
         WaCh7mtU3aypNbFF+aOR6JpBRgliOySQJYR069Ck+lpgduReR5qtvNlGhdBVMeib+q/W
         sZXtiXOkMqkEwFop0n+in7zmfjaYxdrTWzwNaVyO/UygsC03VLu4LQk0xJ7mAPX/yDxe
         zkIQvJybcQq2eoJUisiYhUuj3vVGy6k7CeHQqZhCWkg4oa67iuEHRAPEVedcB7ZJTaAC
         D9XQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Ldid8panXO1lTZt6Y+QBMsk36ebcjiJW7hI01WkdFDU=;
        b=QR8jA4jW08/xT76KY5Ix9GZPyvgHFp4E3/WE+Nq+VwlvI+sdTRU7NGK/99IWpDXB9O
         vVUKhMtkwNeUvxkYpdLrcaKehFP6N5MiCk42gKSV0kKwodxW2dvlMi/OEL5Xj/OwKaXc
         /j9qrv21cJHPzIZqkEltLzsPC3hrfHZPXpWKX2YV20yKwiPBgUA1RASwpXueQdQV6l3P
         pnnLzdZ41R5Qhgmj930LyGbulpLcKN9ly+hqLiyr/pCTRaEPc9LJJ9MT+h026IeZPNyx
         08ElQRvCYfjXwwxwdoYqnuQkUaf/kqgYbz6+jH7GUYUZic8NLlhV7iGRQzNHRH5S5Kk7
         gwEg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=n5x2XicX;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::a2c as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ldid8panXO1lTZt6Y+QBMsk36ebcjiJW7hI01WkdFDU=;
        b=h0Q3kAeJhKHu/6XGekJO0KiGpcjRvU5NTmk/fqs5LosnvP/ZFZwwuRa2EB4FGgb2pu
         AvbBmHQ58y/OWiAxNMljKAARN8S9Ze698YDIX+QjfFGIw8F3w/8PbdIftqEhw58ySHX+
         8AX96XEbWVE/YVycL1L686XVl3ivBzh0v5LE2PAWm86sPALPAXIm7AVp9P1/N4a09lwU
         tG2EMzEmM5CrFBclevhUNOHp3+fyrII0GZWFc2CDkwfM9fjpeNfMTwRW6rIsCNQkVHCV
         2J43TsCDaoKjAYKP4ydmtjbIGW28pD/XM8DR+o3X0iJPJEJBD90cDm6nLH3m0gVzs42q
         98Mw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ldid8panXO1lTZt6Y+QBMsk36ebcjiJW7hI01WkdFDU=;
        b=GWECSBOSJMhSn4P575VljG+Jb0ItulXu0D/Szb0dJbHWcM98m+tBiSALZeOZiGgqLw
         fpOQ177dc8jUxaaZL6Sbawuk7dB1q03vz8eJ0hGGTIiDzJTShFgiVGdWwAbsUyLigL9p
         k0WmsDO0M0SQJxv2XC836t3aI2oRNbEOKe2PgigCJ9ff4RsWZtvB70g+RUFD0Fa5j/fC
         decnv7CWaxtUyUUu+rdGeYej1+jYdohuL+wa6v9kp5kETPg+LdSdYajwgNqhikWDKhho
         Glq3fxZzGwxTfX6ePuna68pFWLQOHs+w4yeI0sxrb2xu+xYPozkYTI4k2rrGA7YvEN9X
         D78w==
X-Gm-Message-State: AOAM530XIYJ7ovBsXJdBzvPAFHWuhntOsR/N8IX4JH2tzWd83k7WqZA+
	1N2TO9ToqJjQPfrsrjzfHIA=
X-Google-Smtp-Source: ABdhPJyDlCcZ6bqwxqV30pu26g8NsL47gly3Tb4zwu/wXbyuXv1uUTotliS9o84wEA0texyUBec2iQ==
X-Received: by 2002:a17:902:7795:b0:158:def5:526 with SMTP id o21-20020a170902779500b00158def50526mr6296795pll.0.1650658113421;
        Fri, 22 Apr 2022 13:08:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:c4f:b0:1c6:8749:f769 with SMTP id
 u15-20020a17090a0c4f00b001c68749f769ls8549123pje.3.gmail; Fri, 22 Apr 2022
 13:08:32 -0700 (PDT)
X-Received: by 2002:a17:902:cf0a:b0:156:39c9:4c44 with SMTP id i10-20020a170902cf0a00b0015639c94c44mr5962971plg.124.1650658112795;
        Fri, 22 Apr 2022 13:08:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650658112; cv=none;
        d=google.com; s=arc-20160816;
        b=sbkGSr95KSOsvV1G3dx5AApEk4bP58JKhu9DzIRBXf7HLnmXvXjvXEy0eC1krTs50B
         H6g0BO1G1V8vQl1ofo4HRCkKbGZXYUB+3vOznGaobVPriNryzf1FQMys/yyK5+DQl5No
         CYT2BeAnPgpzl7TSu0K8b07wi493irL3wjaZcHedHtQ7e6K16EKDKJm3FtCispfquxW7
         wLdKDvSkcQJskK2gHkcavsajhHVVJbxYZ+nnN8tDicPYXVQC3sFv5Rk/Qse6WGYK9xDS
         vZ/qsI5Ul//9J50G9ClaEE6YKDEZh1fNReEXuYEyyjtEG8g0pUeMzdecajzKVTdDCHOF
         YUaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=oe1v+8HKmPN5xE9lG49dcb7rjaDAxWTXKsNw822YQmM=;
        b=mWHwK/P9rzE5kdLaNIWUjcZOX0Ma65PGKA992IU+Oxe9MMHNCGw6Vjw1qwBesaRLEw
         lUS2L+gcZX9IK9wcLdoNKgfRuetpoDPMMSAdtLim944QQDvwRvy0ETBK/sJtTW+avHEe
         O9evx5ftmGXheHptOiK83SuMLjhoewgunhgjqCzXcWG2GX2sOMVbBRqAO6/YFH2+PWQN
         joHvVvXklT3oa9qE9o6gODGI4MwaqBv7KycGO/cv6NVuW0Ue23fRBJyyPzsOP+aWvRtx
         88HVfgcrdiahPJe0yPtKRfmrblQ3Fe1mRNAPmhV2H7/0XVtGe9ldQn81m/eTQ82/kWet
         VetA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=n5x2XicX;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::a2c as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa2c.google.com (mail-vk1-xa2c.google.com. [2607:f8b0:4864:20::a2c])
        by gmr-mx.google.com with ESMTPS id q21-20020a056a0002b500b0050ad2fd0312si705059pfs.5.2022.04.22.13.08.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Apr 2022 13:08:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::a2c as permitted sender) client-ip=2607:f8b0:4864:20::a2c;
Received: by mail-vk1-xa2c.google.com with SMTP id bc42so4331511vkb.12
        for <kasan-dev@googlegroups.com>; Fri, 22 Apr 2022 13:08:32 -0700 (PDT)
X-Received: by 2002:ac5:c899:0:b0:349:33e8:d676 with SMTP id
 n25-20020ac5c899000000b0034933e8d676mr2382122vkl.0.1650658111910; Fri, 22 Apr
 2022 13:08:31 -0700 (PDT)
MIME-Version: 1.0
References: <20220421211549.3884453-1-pcc@google.com> <YmLt0s/KdSJlSSPk@arm.com>
In-Reply-To: <YmLt0s/KdSJlSSPk@arm.com>
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 22 Apr 2022 13:08:20 -0700
Message-ID: <CAMn1gO77+Smgezkx0o5t+MnLJK9KUNpEb+xiJ3Pkoj4pFD1JfQ@mail.gmail.com>
Subject: Re: [PATCH v2] mm: make minimum slab alignment a runtime property
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Vlastimil Babka <vbabka@suse.cz>, 
	Pekka Enberg <penberg@kernel.org>, roman.gushchin@linux.dev, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, David Rientjes <rientjes@google.com>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Eric Biederman <ebiederm@xmission.com>, 
	Kees Cook <keescook@chromium.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=n5x2XicX;       spf=pass
 (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::a2c as
 permitted sender) smtp.mailfrom=pcc@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

On Fri, Apr 22, 2022 at 11:03 AM Catalin Marinas
<catalin.marinas@arm.com> wrote:
>
> On Thu, Apr 21, 2022 at 02:15:48PM -0700, Peter Collingbourne wrote:
> > diff --git a/include/linux/slab.h b/include/linux/slab.h
> > index 373b3ef99f4e..80e517593372 100644
> > --- a/include/linux/slab.h
> > +++ b/include/linux/slab.h
> > @@ -201,21 +201,33 @@ void kmem_dump_obj(void *object);
> >  #endif
> >
> >  /*
> > - * Setting ARCH_SLAB_MINALIGN in arch headers allows a different alignment.
> > + * Setting ARCH_SLAB_MIN_MINALIGN in arch headers allows a different alignment.
> >   * Intended for arches that get misalignment faults even for 64 bit integer
> >   * aligned buffers.
> >   */
> > -#ifndef ARCH_SLAB_MINALIGN
> > -#define ARCH_SLAB_MINALIGN __alignof__(unsigned long long)
> > +#ifndef ARCH_SLAB_MIN_MINALIGN
> > +#define ARCH_SLAB_MIN_MINALIGN __alignof__(unsigned long long)
> > +#endif
>
> Sorry, only a drive-by comment, I'll look at the arm64 parts next week.
> I've seen it mentioned in the first version, what's the point of MIN_MIN
> and not just MIN?

I tried to explain it here:
https://lore.kernel.org/all/CAMn1gO5xHZvFSSsW5sTVaUBN_gS-cYYNMG3PnpgCmh7kk_Zx7Q@mail.gmail.com/

In the end I decided to go back to MIN so this is moot.

Peter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMn1gO77%2BSmgezkx0o5t%2BMnLJK9KUNpEb%2BxiJ3Pkoj4pFD1JfQ%40mail.gmail.com.
