Return-Path: <kasan-dev+bncBCCMH5WKTMGRBU7S3X5AKGQE2KATUAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 339FC261156
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Sep 2020 14:30:12 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id s14sf4601838ljj.6
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Sep 2020 05:30:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599568211; cv=pass;
        d=google.com; s=arc-20160816;
        b=SUHqtRFDMMMH8tNQFLdbtUnk3VpoFOHOlZXyt3a5q3IqSHW5jAL1knDFxRE/cMSiRk
         h0cn/bc941FjHk6x2jkQ09L2+drwwU94ChF2yIUn5r6kcq37F6F5KTUKrx3LfW9qjUAt
         xgfxEVLCGttySqZJyJ63RKdt5e1Gir5OyW2CYZURTgub102Jmb4ciIZ2VDKCvVAijNid
         h+yMc+NpS8wwex7O5uUAdorkHHlnykkSRQRyiVW5ehC5TOkikx0dc3Ic2IGywTXlRax7
         YtoDGQVuLnEsXA4qwiB36OfwQhwjB1rC2lwo2e5HqgBelG1hkwOlouijqiCfrHoYvL7o
         PVOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Exd0GIFPrwV8IMxEjclkSefeCk1CsB9wy5D/7HxeQrM=;
        b=eOb23ZeJJEsIkt3CPNfDzT0KozLB6ebyts5l8JzKjQk7LTsmxq49n/ehMcO8QApU5e
         5YWiqJvnX12jGOz79GceYxq5An+gbSBSShAudbRpcLBa+EwmJeGgIZj5odqBYYDfmPZ5
         yNSf5firBRevCo+PdivYLfcWG5nhHeGmmbEOtEkRGobZWEgwjqp+5y1yColrZHLnoi94
         DdkvLf3v/V2xsjybEMybFOb25WeQFxDjhenqqnJLWWH0g+OKAgDZ+AzhMh0owOFOtcU2
         CfuXeJjlQyof4AZrtZCMxWG5FeEaAntkfLxIsAzPSdzTYUxP+kstgzO3lAP4Oof+o+nB
         LbvQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GbC0SGU+;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Exd0GIFPrwV8IMxEjclkSefeCk1CsB9wy5D/7HxeQrM=;
        b=fx8GaIddd/XD65//61I6bQEyRC49h+1+tUo+AED1Be0L4LeK8dDmtysYbfq6MhknFt
         ZECwZGISUcuqKnvM7e9I+AcWD84PyaB1n2uI34JylfOlhK8fO+Ep3j9Ulzm3NpbXDFfL
         L147DnSNALKsv3ZUFeVPINaCIzAvohsaLIMo1JrPXorEz6E5fwSrrCX55SnClIgzNuCv
         p121gBm/UAlxIwgu9xKaQo1MeH6PS3TqbXfiaToE3GUMlqikJINLzhi5oeIFn6jFHikC
         YyqUpFHH1GKuy9DHpEbi4FqIZpbSi9E+wzn383dVFAanUWnsi99Mn0qHDYcv+w1teDsl
         uPKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Exd0GIFPrwV8IMxEjclkSefeCk1CsB9wy5D/7HxeQrM=;
        b=of+UjHplY5pj6Hf+R3QYrccO5zmOuRxpj8J7+OMH1XGaO+QKillt1dl1jRyZNsjsTK
         mK5Zfh6n3WIGu7nCXg7GMx3n3tYAhzkOhSwnN1LYSZP+4jH3FNAeBRNA2Ac37q15N1qx
         Z8jmhe8l/GjJ37cFgUYd/YYICWm/nmuwJpzTlxRKFh6PtSMD0MSE65Jn0x/7ITBNbg/r
         i7DSantn7iz9aUjhNtsd6iB/esmghdzr/AlZN464Y6fSI0rnlFFg+158Nwg7WnfBkYRz
         19k4ptpSFNHSKEujXzD7cjGDVI0CoM+aMHtbVK7yD5DzTnf63hFG66CoFeQv62X4ChJm
         UGBQ==
X-Gm-Message-State: AOAM530weAwpPMzaaAkhzeFgiYxqyil0xMEwPZHPso5OqhEmAaaXnpAf
	wQto25+zMUEshLnWJ1QjUuU=
X-Google-Smtp-Source: ABdhPJxOKClnZM98HZcU88bYWn/pKcB/VTuREF5Lt3sS1EBetPaVtM+b1dXkFm/0DRgL6Yu38xg5eA==
X-Received: by 2002:ac2:5999:: with SMTP id w25mr11958221lfn.67.1599568211769;
        Tue, 08 Sep 2020 05:30:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a556:: with SMTP id e22ls91175ljn.9.gmail; Tue, 08 Sep
 2020 05:30:10 -0700 (PDT)
X-Received: by 2002:a05:651c:124b:: with SMTP id h11mr13402563ljh.172.1599568210714;
        Tue, 08 Sep 2020 05:30:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599568210; cv=none;
        d=google.com; s=arc-20160816;
        b=Fk8kwyxYmFv/0JrQTI/h2VyYIsvl48939LzQakn5pYUMPxJxCZB7erpzXzjtVnEh/G
         aLIMmWBppkAnJjhx1rRPjtB5hpOzt4h5pUeLJcxGVq2MkltzZKuZChpi+mT+gY69ge+c
         UEM6Z+y7UhmQRy8jAuA4DT18rE9XOQlfrW9lfo0H2ZulGR4hChsdLgYY2BAFRzZiNwMO
         FrTIiegPXh3rKioaRYownV7R5Pp/CyJZQ5OrO1GoLvQE9zPFZfTrTDI+V7uOqif94o8R
         36aSqm3pScqRUyqr7oiBLGSnR/37upkDfxG94JeupADiGFQMvJy48myKQwzk3GujGnHt
         dgQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=y/EkIKvR6iBw+zS5qhGZEpN1iwHB9TWxtJTSD07C3J4=;
        b=urU9MUf1ss18BAmVblyMuj3sEIoZnTUISfSBP7hnwU2ihIl9N/Z+0998WnB/2cupas
         GBPDwZx3pRW8eUqKQASp78RCczeJo7UCCdY6fJZwkV6V29WMCzDHhEq8VXC/S7BLchiv
         tUYSA5csYygrrruqkUFf8BBez56MxzQdHYwfTg3Rj/+tZVJeV5RP8v9HhEz9VK6EM24J
         MUSwv3IkAIYIJsIpVEPCrSOhAb81vilmhuojdupX8P8FYZqotrcGw69nikuPNegkFcr/
         YwV/ogcH8W7IQBnB2h8TuQlg9QyqjmkB0q223m6ksctXvgF6534kAGMVKvBfnNczKla2
         E5Wg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GbC0SGU+;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x441.google.com (mail-wr1-x441.google.com. [2a00:1450:4864:20::441])
        by gmr-mx.google.com with ESMTPS id 21si463572ljq.5.2020.09.08.05.30.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Sep 2020 05:30:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::441 as permitted sender) client-ip=2a00:1450:4864:20::441;
Received: by mail-wr1-x441.google.com with SMTP id c18so18880866wrm.9
        for <kasan-dev@googlegroups.com>; Tue, 08 Sep 2020 05:30:10 -0700 (PDT)
X-Received: by 2002:adf:ded0:: with SMTP id i16mr28452918wrn.372.1599568210306;
 Tue, 08 Sep 2020 05:30:10 -0700 (PDT)
MIME-Version: 1.0
References: <20200907134055.2878499-1-elver@google.com> <20200907134055.2878499-8-elver@google.com>
 <20200908115316.GD25591@gaia>
In-Reply-To: <20200908115316.GD25591@gaia>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 8 Sep 2020 14:29:59 +0200
Message-ID: <CAG_fn=U8tv2tXdWPTakcpDKG253kHj0YdsSU46GA5WgMo46BWg@mail.gmail.com>
Subject: Re: [PATCH RFC 07/10] kfence, kmemleak: make KFENCE compatible with KMEMLEAK
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Mark Rutland <mark.rutland@arm.com>, Pekka Enberg <penberg@kernel.org>, 
	"H. Peter Anvin" <hpa@zytor.com>, paulmck@kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, dave.hansen@linux.intel.com, 
	Dmitriy Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Ingo Molnar <mingo@redhat.com>, 
	Jann Horn <jannh@google.com>, Jonathan Corbet <corbet@lwn.net>, Kees Cook <keescook@chromium.org>, 
	Peter Zijlstra <peterz@infradead.org>, Qian Cai <cai@lca.pw>, Thomas Gleixner <tglx@linutronix.de>, 
	Will Deacon <will@kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, linux-doc@vger.kernel.org, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	linux-arm-kernel@lists.infradead.org, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=GbC0SGU+;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::441 as
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

> Could you instead do:
>
> #if defined(CONFIG_KFENCE) && defined(CONFIG_HAVE_ARCH_KFENCE_STATIC_POOL=
)
>         delete_object_part((unsigned long)__kfence_pool, KFENCE_POOL_SIZE=
);
> #endif

Thanks, we'll apply this to v2!

--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DU8tv2tXdWPTakcpDKG253kHj0YdsSU46GA5WgMo46BWg%40mail.gmai=
l.com.
