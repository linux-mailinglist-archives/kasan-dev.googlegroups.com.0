Return-Path: <kasan-dev+bncBCCMH5WKTMGRBZU776OQMGQEN7NMAUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id EA1DC666DE2
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 10:16:23 +0100 (CET)
Received: by mail-qk1-x737.google.com with SMTP id y6-20020a05620a44c600b00704d482d3a0sf12795850qkp.21
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 01:16:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673514983; cv=pass;
        d=google.com; s=arc-20160816;
        b=oyab/P6S7Ovb9yl4tQaiLh74/9Huzrcv4Lm7jAJT1gUjQf+OkGt5TEvZSK4eKy8tNq
         xyGiWXY+QXlATw3zXvYp6to0kKg/eMNeuat3bS6NyltySsn/R8gfQ1KFAP3kno+XwnD2
         q91H0NGwYzuXDJEiLSiYjUfcTJKF84H2YuWuEoPM69BbNWDaTbq9+HD4kfr5pYAwYwQz
         cGIOzHHjdYjKJr5o1TLrccSLSgZ/24QAONvdp+P7PQC+rNKVY7uFZp9RIlUXSexz8mTN
         54zNxiFAmyBuKstBBLlrU6bRZDiiYp1eLG7IAb4pgB7rshepvktzFMrwoHs0pAzrB19D
         twyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=c70hvgDXb2Kk3rOUPetpEHLTtpeQxZmmIU1y14FzK4k=;
        b=CBEkEjNP4cwCoVQhRnNg0QUSfsy/j90z2O1ZMDnx8pp2wXpvJ0a5ktoovaDuyiXofM
         3xZYrCDLrCIgPfWhyWlVf98GL72NafHTKFAxX4LpsYlg/euI0kWd5hpuSt2r7OFF+wCf
         UYZfgm961OGhWAxFdrB347tA5b5Z4V7nSDZJZVhZQgbYivzCdadvE0zaKhNLpRU/U2xo
         sk59n+Mh1We3LP89tzUu6MsbutbVVja5d4x1bFlshBWkLVkQLtxYuOGCexFI9dxK2YdK
         DWE0eTCbX8awjt9aWrGUew1E+FfoxCloDOMNkv1TdT6sBQxtGwI9BPxJLGqWf50FO0o6
         JTmw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DIk2ZbXA;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=c70hvgDXb2Kk3rOUPetpEHLTtpeQxZmmIU1y14FzK4k=;
        b=pL0OEu1yLO3/VwAJoGF/XFrl8cMsqKUyPFQmQJlU3HdCYE+rk82tzfjStJFb0w/HFx
         evHPtpEFX3KKRZdhzdqGNIxV/A7VbdhNkdou5oinNuWlqDHYFoICbpg/2sh20YIrbgLd
         +L4RRt2nerbbAXX2oKuGD40fq4n0EB2Dyjk4xUy/oNXvPYY0FSSNJ7b1e6L5VrMF56gG
         Pur8Bimc9/hn/8vEcd0JOj4bg0SOPHPyPaoKi9BabZLShklt8eiBe8paC9oeeIP8WZi+
         fub2RNIq12QZ2akyVAXPYXBrYogdB+iHdAoxmJEJM4qI9JuaO5LBtP7AnWyBSp18sN4K
         QWLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=c70hvgDXb2Kk3rOUPetpEHLTtpeQxZmmIU1y14FzK4k=;
        b=xu1yExPB88G/Ql65L9xW5a1ivXwkjLf9Zj9vBFFZw3lVSgzzcXoBqB5kW6+TPuRjKr
         4RE/fSrbeKPPiEJMIkLzqNyX/dArEyVivYzRqaFRJ8cwA0Wep/4daB3/vNP6+u98gAsP
         7usIuMIC5nEnKmofTs0jQtvn8WZEM5i5HtVdawwbfsFOebIuRaAQttKgTPRBpBxrq+7y
         ZHrfaTgETm7TQsI8H26whl1sfIQaaUvctpzJIQXB9hLdg68Y/zwNqnlc6HLylzi7XZS/
         DgfmJxELopoNxZl+uPRVfej2WNeomy8o8alpcXkAD5hKD0jAWUDDyTGDlTcQ5kSCl3cE
         rB3Q==
X-Gm-Message-State: AFqh2kqE9YPAWT3qm9oJbSIKCfI5GMsMxDcun35Wec9Krz4NvSPgDjvG
	FG0cHCeocGSqGGll7uwR6+I=
X-Google-Smtp-Source: AMrXdXtUevjoTP/G1HftRZmQomExzfdl+Hav/B1zB0oBmy28HLVUA8P3QeVQOi+vaxt3qPnYfMzgCg==
X-Received: by 2002:a05:620a:167b:b0:6fe:cc8b:83 with SMTP id d27-20020a05620a167b00b006fecc8b0083mr4941959qko.481.1673514982700;
        Thu, 12 Jan 2023 01:16:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1b25:b0:3a9:8ab2:1bab with SMTP id
 bb37-20020a05622a1b2500b003a98ab21babls1317520qtb.5.-pod-prod-gmail; Thu, 12
 Jan 2023 01:16:22 -0800 (PST)
X-Received: by 2002:ac8:1344:0:b0:3ab:5d1e:a775 with SMTP id f4-20020ac81344000000b003ab5d1ea775mr98074334qtj.12.1673514982089;
        Thu, 12 Jan 2023 01:16:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673514982; cv=none;
        d=google.com; s=arc-20160816;
        b=L4vu6poTHB0ToUM5XwKTz7yoHPj3yVcBBwSd533Kindcs047FqXTrnw823r6Lj8K1R
         bn48J/eQGbzoZfONvZA6eWn09v0bSG4FepeHBWiCm2c01xEGvrb0EHeQE8fU/5qxMNat
         NuOmDAgopwCFwnFJVdadkgufNQ4gHKnx8r7lceRrm5Ya60ZtqijyTnrjkoggq0tiwsNP
         Amz25CKr7CdjsdtJFEz8+8H3tNLdzOhz03CU6t5mDdOFNIf0mTmUGFhIejp6av+dcZFt
         T4ItKXODV5h6CFOYFbdbnNnjdn0fxKHEAXTiC/ZpOScBH7j0f5tpnIOaGj+IN0kI6VBo
         ghrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=dJZw00JqIDxZsH6vnh8PN+9M8r5KlwJJ+NaoX/4aFqY=;
        b=Ush6HnCCfgTf01RCEm+x0w+hNHgBe1lTi2EAEPQxQsi8NaUiMXmNl4I/Qaw/lkwnXX
         tgEAkLlroHxbW5+5v+IyOqQ2lmN5Nc4xuSsWCKKvXxdrf9oE6SuHDB/NrDMwVVnIlgMu
         zFnxO9rtVO3m2gx8Phsp5X2yWLCxtMqCeDCLvbAIM8Mq12z24fTyEDAekRgLGVWcvP6c
         o4mfT8JyG8sOPDHv0WljtXqzJljx7jrySS0vF+V7o7ffkeyQxsgesafI55d6Aho2AfSl
         Vhp0yHTgE7O2qpYEbkg0ZHraaoteZ00jAtNw32KzfoMl0tsTis8/QgrIoheGpKpREKTL
         WPOA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DIk2ZbXA;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb29.google.com (mail-yb1-xb29.google.com. [2607:f8b0:4864:20::b29])
        by gmr-mx.google.com with ESMTPS id e6-20020ac84b46000000b003a803b27748si1053846qts.0.2023.01.12.01.16.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Jan 2023 01:16:22 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) client-ip=2607:f8b0:4864:20::b29;
Received: by mail-yb1-xb29.google.com with SMTP id g4so17929556ybg.7
        for <kasan-dev@googlegroups.com>; Thu, 12 Jan 2023 01:16:22 -0800 (PST)
X-Received: by 2002:a05:6902:1c1:b0:7c9:71e:e241 with SMTP id
 u1-20020a05690201c100b007c9071ee241mr139273ybh.242.1673514981561; Thu, 12 Jan
 2023 01:16:21 -0800 (PST)
MIME-Version: 1.0
References: <202301020356.dFruA4I5-lkp@intel.com> <aa722a69-8493-b449-c80c-a7cc1cf8a1b6@suse.cz>
 <CAG_fn=XmHKvpev4Gxv=SFOf2Kz0AwiuudXPqPjVJJo2gN=yOcg@mail.gmail.com> <953dda90-5a73-01f0-e5b7-2607e67dec13@suse.cz>
In-Reply-To: <953dda90-5a73-01f0-e5b7-2607e67dec13@suse.cz>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Jan 2023 10:15:45 +0100
Message-ID: <CAG_fn=Vz47zvCDoUENX5kH7Giena+w=yifWbMo28ayAUKU7kyQ@mail.gmail.com>
Subject: Re: mm/kmsan/instrumentation.c:41:26: warning: no previous prototype
 for function '__msan_metadata_ptr_for_load_n'
To: Vlastimil Babka <vbabka@suse.cz>
Cc: kernel test robot <lkp@intel.com>, llvm@lists.linux.dev, oe-kbuild-all@lists.linux.dev, 
	linux-kernel@vger.kernel.org, Christoph Lameter <cl@linux-foundation.org>, 
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=DIk2ZbXA;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b29 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

> > Would it also make sense to exclude KMSAN with CONFIG_SLUB_TINY?
>
> If the root causes are fixed, then it's not necessary? AFAIK SLUB_TINY on=
ly
> indirectly caused KMSAN to be newly enabled in some configs, but there's =
no
> fundamental incompatibility that I know of.

So far I couldn't manage to boot KMSAN with SLUB_TINY, it just dies
somewhere very early with the following stacktrace:

#0  0xffffffff9044134a in native_halt () at ./arch/x86/include/asm/irqflags=
.h:57
#1  halt () at ./arch/x86/include/asm/irqflags.h:98
#2  early_fixup_exception (regs=3Dregs@entry=3D0xffffffff8fa03d08,
trapnr=3Dtrapnr@entry=3D14) at arch/x86/mm/extable.c:340
#3  0xffffffff903c23db in do_early_exception (regs=3D0xffffffff8fa03d08,
trapnr=3D14) at arch/x86/kernel/head64.c:424
#4  0xffffffff903c214f in early_idt_handler_common () at
arch/x86/kernel/head_64.S:483
#5  0x0000000000000000 in ?? ()

The same kernel boots (to some extent) without CONFIG_KMSAN, so my
guess is that we're instrumenting something that is not supposed to be
instrumented.
But SLUB_TINY doesn't add new source files, and it's also unlikely to
kick in before mm_init(), right?

--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVz47zvCDoUENX5kH7Giena%2Bw%3DyifWbMo28ayAUKU7kyQ%40mail.=
gmail.com.
