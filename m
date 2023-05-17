Return-Path: <kasan-dev+bncBD52JJ7JXILRBRXUSCRQMGQEOKDQREA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D97C705D14
	for <lists+kasan-dev@lfdr.de>; Wed, 17 May 2023 04:22:00 +0200 (CEST)
Received: by mail-ot1-x33c.google.com with SMTP id 46e09a7af769-6ae14e743basf88154a34.3
        for <lists+kasan-dev@lfdr.de>; Tue, 16 May 2023 19:21:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684290119; cv=pass;
        d=google.com; s=arc-20160816;
        b=ODVz0herN7tPfVuO6YYDbBFX82LVPlUhZh8kMOJAoroHNb9yEAOGmFIoIG3xs8wu4F
         mMtRlXkHeVHHd0eYShbci2qpvG1OFXNP1FwwMu9A1paaysb20PbITLWgu3sa4eB8T05b
         RlzQVNmydFcB7eUIFDCz5ap8gf6f+7Y8VPVo/iJX3fDJ6VkfVnMMZ8esj5m0NVb2rM2N
         LUJ1cEYW42ulEGdYpCAl9vZ3iyEzMxc64ZzOpff4Ri5E1pFdgVIW7Hwwhqqy/RA+KP//
         6JcV+80DhVKXl81DW1n45r9yMyB79U5BpMKtf52AOk9gWZjYzxPYMzu48UPq6EWWu2nS
         clFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=j/Va+p2bzbm8VE0VxIPQZ5MwP2/moamptr3CKrCx27k=;
        b=CupJFKZ/+bSOCUNLI+Z6qzVLMR7aX7YBVImBpcBzW777fgat9Xf3VlWDHD6JWH4Xoc
         Rbz9xR7C+EN0EfE74wPtXC6Uunbyj+7V+OAjAHEgCOV4xPaddfrenmdleQKoGDqkdoXY
         cHz2LcuzzGvfjVRilpoeBO3sfrQRNPwziGK1iFYTUTuReeS3rfsgKTDJK/ZHqAevngJS
         /K0odQsFANPq4JIl6QhT4SDPQneJET100iwhR5qDCNFgKIzoSwEPKVGmHQoBBUQhJi8+
         2uVshRqyT9rUpc8qv74IuCcQkl3ldlXzrnLfFaYejqj0EYbIuzDlklxJD6dHqtx9rQPJ
         nr4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=PZR0hZsH;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::12a as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684290119; x=1686882119;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=j/Va+p2bzbm8VE0VxIPQZ5MwP2/moamptr3CKrCx27k=;
        b=pK/bav2XPQ593dH3S2GSqkw+WGqpl1m8QMpMDUupl5qpCoucEKm8ufoxAAS7IkoL/C
         BbyY+tovC8y9Ir0Welr2B8669n27ksiQjJ0I9SaZ09qorpLqakJfG9T4XPOfD+YMul6j
         JggO1xhf+311OYmAin3H0kfb918GSLb0kaDHIt8MIIQMEmlHDrn40hsL6HDtKSyUHgwR
         BFCqa8EX4I1rK6mBKdqjRTsdfczpGj8ZxSjl7XpGO3INEdv1XyJEdpMvpKIvv5xma7jR
         fQHdATyYcL173P0Utd+qafaJj1RcIKE1ZnwMExbiNEm+n1BH0Qk5A/C6/6HReL2tT9d8
         20Fg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684290119; x=1686882119;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=j/Va+p2bzbm8VE0VxIPQZ5MwP2/moamptr3CKrCx27k=;
        b=AHr/ngEeGYffZen9vifAEi0TY/kfljwjZfs0zxogdLERQTI0HWcDPuTUWTENe3HEcH
         i3vEhFLoUWJmbJDE7NxuizRE08rH5UwNyAAbpRQDqEH4CnjWI0aMAu6ob975u01QoZYN
         jkTeJJ+dwx8KNmcMuyh9lowY4WCQ4+Nont9+6+I9db/0yd1fn0BII9hsB7llL/QULcHF
         rCvcL84aABqpOUfN6ZnsUhIjpa3j10M6jVRhLHDf2OxnAne831wYJiJPZ1Vj97WW4Xwd
         mhQ/nVnqTcbMF71Xq/uBEKHBC6T2Q4/UedZxh+7H54kkXrxq4hsOlKh6IeKt70LTb1uz
         nEOQ==
X-Gm-Message-State: AC+VfDx4VcovPbtBcUrxYqvvlm/KDBMMy1x1v5o+I9my+sAuEOXy1Rs9
	qzomOB61yUNENpLY513e5u4=
X-Google-Smtp-Source: ACHHUZ5X5y3d7A1rS8quRmo000Vf9T8/O/5LCIU0dLeiEHQL6T7+nPgDJV6diDSg4h8+lK6wGCWrqQ==
X-Received: by 2002:a9d:7dcb:0:b0:6a4:4e5a:61ac with SMTP id k11-20020a9d7dcb000000b006a44e5a61acmr7370475otn.2.1684290118879;
        Tue, 16 May 2023 19:21:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:d990:b0:18f:9d2:8d6b with SMTP id
 gn16-20020a056870d99000b0018f09d28d6bls4065820oab.7.-pod-prod-gmail; Tue, 16
 May 2023 19:21:58 -0700 (PDT)
X-Received: by 2002:a05:6871:40f:b0:180:2a5e:7f8f with SMTP id d15-20020a056871040f00b001802a5e7f8fmr18084825oag.22.1684290118399;
        Tue, 16 May 2023 19:21:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684290118; cv=none;
        d=google.com; s=arc-20160816;
        b=0+2qpcpA/rO4s7z9zKtyWFvawd/Wz4VDrJiWDP56j/kGnqNhTKOVy27ULhfIOaKzhw
         nHu3fcGr7g0oNAvyBZ9wpUMD/X9wTa7zLMc7HsJlsAE8LH9z00fMp9APlznP/3ksHp3G
         CFwPwQWOZaTvn1SFsE3x39AI8rfacZudTE2inaQC7TKV+znWonG7gJ3atZcLTi2PYk5F
         9nDBHkfOEOnknSTY5i8JYPgzu66QcVb9fIwgsiLJR2dRa4ziBgYF5+hEJZlZXSnaDsLb
         +rYoCFwPWY7GFk8ikaBiON60wuLyX49ijJjBl+3FKllAjZ4DOJvTsFr2b71u2/avAAZJ
         l4OQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Z64Nmm8ZHGuJuP2MvW1StM+AVoYaW6xT6Xus5TrlYVk=;
        b=zGpRS4MGz8LnSySjnpNe6sqHL5Qt58Kvs50l4MYqPCxaQ2R4kIYvWW1495GXefzksG
         vr01NrgYxYkA1F/W1envRRMV78LWnIrd6wDxMwnIGFvM+DBOQJdBR2Ml+WhqbmA/2wEq
         BmXZU1vJGoJEVyYgjmXn9ipVmqBeCTqAkLg5eOYpkjA1tMd3RGVhDIsTz3UhfbsCH2EF
         /wW4RkEEO5w8gPUwgkBCMeYcsrqPelNFPMygLFT1dMa1phai7k8U8MDhHA6f5/TL7oQs
         l28HhcjezX7Dcdhi3HQnzMXFnVYok6slhfUcbUh5H/RWOQexrhGpwvvpv66cy+gyj/VL
         UpmQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=PZR0hZsH;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::12a as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-il1-x12a.google.com (mail-il1-x12a.google.com. [2607:f8b0:4864:20::12a])
        by gmr-mx.google.com with ESMTPS id hp25-20020a0568709a9900b001934f67653asi2930556oab.0.2023.05.16.19.21.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 May 2023 19:21:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::12a as permitted sender) client-ip=2607:f8b0:4864:20::12a;
Received: by mail-il1-x12a.google.com with SMTP id e9e14a558f8ab-335d6260e9bso30665ab.1
        for <kasan-dev@googlegroups.com>; Tue, 16 May 2023 19:21:58 -0700 (PDT)
X-Received: by 2002:a05:6e02:2169:b0:32b:7232:dac6 with SMTP id
 s9-20020a056e02216900b0032b7232dac6mr182448ilv.18.1684290117851; Tue, 16 May
 2023 19:21:57 -0700 (PDT)
MIME-Version: 1.0
References: <20230516023514.2643054-1-pcc@google.com> <20230516023514.2643054-2-pcc@google.com>
 <342d76b0-a94f-902a-c701-04a1e477b748@redhat.com>
In-Reply-To: <342d76b0-a94f-902a-c701-04a1e477b748@redhat.com>
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 16 May 2023 19:21:46 -0700
Message-ID: <CAMn1gO7BZ0C6VfE39+_QT+oOWWZ86M0BGEQPu=6Y8+ij1jAUCA@mail.gmail.com>
Subject: Re: [PATCH v2 1/2] mm: Call arch_swap_restore() from do_swap_page()
To: David Hildenbrand <david@redhat.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, 
	=?UTF-8?B?UXVuLXdlaSBMaW4gKOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, "surenb@google.com" <surenb@google.com>, 
	=?UTF-8?B?Q2hpbndlbiBDaGFuZyAo5by16Yym5paHKQ==?= <chinwen.chang@mediatek.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, 
	=?UTF-8?B?S3Vhbi1ZaW5nIExlZSAo5p2O5Yag56mOKQ==?= <Kuan-Ying.Lee@mediatek.com>, 
	=?UTF-8?B?Q2FzcGVyIExpICjmnY7kuK3mpq4p?= <casper.li@mediatek.com>, 
	"gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>, vincenzo.frascino@arm.com, 
	Alexandru Elisei <alexandru.elisei@arm.com>, will@kernel.org, eugenis@google.com, 
	Steven Price <steven.price@arm.com>, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=PZR0hZsH;       spf=pass
 (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::12a as
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

On Tue, May 16, 2023 at 5:49=E2=80=AFAM David Hildenbrand <david@redhat.com=
> wrote:
>
> On 16.05.23 04:35, Peter Collingbourne wrote:
> > Commit c145e0b47c77 ("mm: streamline COW logic in do_swap_page()") move=
d
> > the call to swap_free() before the call to set_pte_at(), which meant th=
at
> > the MTE tags could end up being freed before set_pte_at() had a chance
> > to restore them. Fix it by adding a call to the arch_swap_restore() hoo=
k
> > before the call to swap_free().
> >
> > Signed-off-by: Peter Collingbourne <pcc@google.com>
> > Link: https://linux-review.googlesource.com/id/I6470efa669e8bd2f841049b=
8c61020c510678965
> > Cc: <stable@vger.kernel.org> # 6.1
> > Fixes: c145e0b47c77 ("mm: streamline COW logic in do_swap_page()")
> > Reported-by: Qun-wei Lin (=E6=9E=97=E7=BE=A4=E5=B4=B4) <Qun-wei.Lin@med=
iatek.com>
> > Link: https://lore.kernel.org/all/5050805753ac469e8d727c797c2218a9d780d=
434.camel@mediatek.com/
> > ---
> > v2:
> > - Call arch_swap_restore() directly instead of via arch_do_swap_page()
> >
> >   mm/memory.c | 7 +++++++
> >   1 file changed, 7 insertions(+)
> >
> > diff --git a/mm/memory.c b/mm/memory.c
> > index 01a23ad48a04..a2d9e6952d31 100644
> > --- a/mm/memory.c
> > +++ b/mm/memory.c
> > @@ -3914,6 +3914,13 @@ vm_fault_t do_swap_page(struct vm_fault *vmf)
> >               }
> >       }
> >
> > +     /*
> > +      * Some architectures may have to restore extra metadata to the p=
age
> > +      * when reading from swap. This metadata may be indexed by swap e=
ntry
> > +      * so this must be called before swap_free().
> > +      */
> > +     arch_swap_restore(entry, folio);
> > +
> >       /*
> >        * Remove the swap entry and conditionally try to free up the swa=
pcache.
> >        * We're already holding a reference on the page but haven't mapp=
ed it
>
> Looks much better to me, thanks :)
>
> ... staring at unuse_pte(), I suspect it also doesn't take care of MTE
> tags and needs fixing?

Nice catch, I've fixed it in v3.

I don't think there are any other cases like this. I looked for code
that decrements the MM_SWAPENTS counter and we're already covering all
of them.

Peter

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAMn1gO7BZ0C6VfE39%2B_QT%2BoOWWZ86M0BGEQPu%3D6Y8%2Bij1jAUCA%40mai=
l.gmail.com.
