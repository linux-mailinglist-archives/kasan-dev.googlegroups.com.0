Return-Path: <kasan-dev+bncBDW2JDUY5AORBCGL4WPAMGQE346FDTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 792F36835F0
	for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 20:01:31 +0100 (CET)
Received: by mail-pg1-x539.google.com with SMTP id e11-20020a63d94b000000b0048988ed9a6csf7158756pgj.1
        for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 11:01:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675191689; cv=pass;
        d=google.com; s=arc-20160816;
        b=ly0fWtOM4dFDrf4xMSIcj6Kuf7IPq7E2LYRHn9wBSDobfTxbsRUwUjXRQomtKA+YpD
         8mH/4CAAxh8lET8GzKaC/OgFQThCfhnMM8Wok6L2QubajHtXE2gbpn0Q0wNwlCNGcd35
         0PSVD3gO/IWqb4atnW71Dk9igOUTSftf21EFr+Rka28Pe0zmBwxs0M9L4oXcGuoDIp4c
         LMv2arE7rpQQ0+PiqoiYtiM3o5nM241B+M4LWL7luXj51utrEJjKKTFBuXjY1Ug3j1YO
         LUrNdhA0rGpyh8xZ3EXQspbJ5iy4vvp5eBToezvNF0MI05yBMUUWCnfvGKehvnR5OpXT
         TnQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=eZK7vIc9phcqLBAw5Ajl72OrQd2MYWmnanO2ogYyVPc=;
        b=a9KNgOy+RSoggcsEYhQmVRfL+Ng3y0y2HIefDMibKkU8+K3+SIFJ9ltzHOog+mlJN4
         sqcekR8495yZNu7+qdlu6m9tEmH6OWIE0d/7Ch9PVge/sxiIPESY5CMnkbckW6h6vJjT
         j0YVtK01a5DpQbd7F3DWSZUgzkp79hA25Fmdt+U3IoEPk8FhmhTTzPrBMBr4wngg++Nd
         GTt2Bg5laBjG1Qgk4ImWR22UqYWP3fs/oFMoomkNlGh0L9CJRlg+lMSt51owQb+sBH6x
         qHQYjXrKS63z5c1JHzi/xgp/mtxLaUbFehNGwscIjj4C/HWZ6b4VCpFJcejAsq2nB+FT
         8C4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=XvW89yFH;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eZK7vIc9phcqLBAw5Ajl72OrQd2MYWmnanO2ogYyVPc=;
        b=mhN6wD+TcvdIxvtQVRU+Nq6akhpfGcRvCXC3/N6h0FJaPL6BFyg3m2MSY3JbXc+uN6
         NgU57YicUT1hMhZ+eBDOA28WKNbwd8gOTOf5rfjgqYzAeHNkvryGnZBPW2DHqDhUDX5D
         8XKYSjRmBLXTQpb0V3Wg29iSSQnEpTlaN/WuLpe8LVlPYO6XErXRyRoiqcBAY8rxgYYJ
         srp1wqwh9bmfxmQLH8No5FRgPCfb0Y7cW0zJr6lKZ3WU2rnBrBo231dVlJRRp6byEFdj
         qlibJaPs/MdHleChMJ+uxFbv+m9wMK25lUwVKpf0qwXNRf3qscuno3Axm2PNqzGAdx4s
         V73Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=eZK7vIc9phcqLBAw5Ajl72OrQd2MYWmnanO2ogYyVPc=;
        b=cABRYtVLyqAUP/Fqu3Wqwyfhg2Mhu0H4TgHyh+zFcL+x+PMOYlVLE1LvG1Ag8bikXP
         jraBywgbIMAArBgSIA7zVO9xEJ3r8tP1rTIXyEIdGW/w2qlc4dP+CWuKdI7BtZubqm0l
         D7nRwv4k3J88wsDRARiogHsEEsDbzoNuOqnUfMYAbCPCQc7TWrMIVIIqt98FIFKeOJfB
         mq8PCyHKkkd6GCeOISgINjb3hXPSW8XwJ2j9XA5BMdfAmaTRWFxZZVzvdv4DUZF7WfxD
         GHP6v6JTY3WsS0M7mUYs5l/TKWgDQ+AFVDJgotLgvosT4Yl3fHUq6Cjq48clTMoxq3Se
         31VA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eZK7vIc9phcqLBAw5Ajl72OrQd2MYWmnanO2ogYyVPc=;
        b=KtwPeub7I82ZgL1ZGWv36TSkzG13QkUGupuqkgfpBJQEL5euwc6rhpcyA5IEsLw/Qg
         IwfpVtKyx/HysiGQedu017oiMExmXyhs9vtwLmvNRN5wO5MuLEltIKfIx8SkscjMXXCr
         6nR6oV4mG569lSFdhqokz9CHlc/YF4MNic9pXypBdbMWOL6V9I9RLDB115YYa8Ri/b+K
         pj6plR2uB4vVlfMrPkIq833nsejiSAxmxVirI9wFHFrTXm8X+zcQejZ5tUgplXGw9R7u
         SFSOo+QNv7hLSCjmP0PgNWfuzs+ALbNeI5abeoqmc4Wv2lKyAd4r6jul54xem9QBAjXL
         llTg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXjF/OkVIwYat/i3RK8mXNhISilQfO2rXuMhkbvdEOx6ghJIxpI
	PODZZpR0MtzTNrKHfmIznOU=
X-Google-Smtp-Source: AK7set+CFTfxxZm8xPpTLsIM7ER8r1mAYiEPdNjodIgKUbKdsyUUbMVlusmH5ljCORnnRBrKWOAZeQ==
X-Received: by 2002:a17:90a:e149:b0:230:821:957e with SMTP id ez9-20020a17090ae14900b002300821957emr894364pjb.53.1675191688962;
        Tue, 31 Jan 2023 11:01:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2cc:b0:194:6afa:c3 with SMTP id s12-20020a17090302cc00b001946afa00c3ls17370474plk.4.-pod-prod-gmail;
 Tue, 31 Jan 2023 11:01:28 -0800 (PST)
X-Received: by 2002:a17:90b:4c0c:b0:22b:f680:f506 with SMTP id na12-20020a17090b4c0c00b0022bf680f506mr29039550pjb.42.1675191688253;
        Tue, 31 Jan 2023 11:01:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675191688; cv=none;
        d=google.com; s=arc-20160816;
        b=QtmFIUA0mIZRRhU8E8ji7gCaxE3lCB6UFZPQDbtyXcs54agFHDMyKqkLLnte8vV+aH
         dp5cdn/zJxDX7oSBPgMj59F6eRZhCPJOev+6af444INSsWAYffjt+eF+bfluZoeocSPB
         3Xid6EVg7fsJvQC1xPLzi87Ce3vWiy4WMAtSQiKkqB8kPjyvfWnnbpxN439+MkBDARvv
         ywXLkVo+9EaVc1bC+OUhUQTt0xK3jzIxdnWIfg7TfnPUEaxzek2BMgA7hbEgXdETdbY4
         T84hPc+PjY8XQlEshz8W0SFcrPVj9zpFontxKNJiM3V4ofIWCtE5Gg7G/s65sxVZ9nhw
         vRrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ee8VrbotWmdr9Bi0GM3TMNLFcbwdi2SIi4lojz2pU58=;
        b=d68iS6NRje4Qq9H0JyKpXu2faQQZ5/4sxjO1KvOMCMBn+3B9450timj3wzfn44+mXi
         0BEro6NQLqSelYBqDwXYHkztXMZHR0dLgLZPJulS0nPtxznyIKLprC3DmqT7+k1nPPrq
         Oaa373F8qYECL1epo//+MEKYtIoba6slNIsljwrjAyqhoJBsJajQC6MI38mcXpYjPpRu
         5+eEsUmp0+7+xwiYXeEtwRNXxm/avw+Sy3ecWDhiSukhCKrsQfjKtnBkSB+G+ghOtSvg
         8n4LweUjdlHmDDnC+pJTIykkZ1+aLI4Ty7m8/AwSqeME6dKMziRApsrckHmUjUdkuRDc
         tzUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=XvW89yFH;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x62b.google.com (mail-pl1-x62b.google.com. [2607:f8b0:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id m129-20020a632687000000b004de8a48e09dsi1145762pgm.0.2023.01.31.11.01.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 31 Jan 2023 11:01:28 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) client-ip=2607:f8b0:4864:20::62b;
Received: by mail-pl1-x62b.google.com with SMTP id v23so16075989plo.1
        for <kasan-dev@googlegroups.com>; Tue, 31 Jan 2023 11:01:28 -0800 (PST)
X-Received: by 2002:a17:90a:cc5:b0:22c:4462:fb92 with SMTP id
 5-20020a17090a0cc500b0022c4462fb92mr3208121pjt.44.1675191687937; Tue, 31 Jan
 2023 11:01:27 -0800 (PST)
MIME-Version: 1.0
References: <cover.1675111415.git.andreyknvl@google.com> <be09b64fb196ffe0c19ce7afc4130efba5425df9.1675111415.git.andreyknvl@google.com>
 <CAG_fn=WnxbcbjfKvRGen7fkKyx_9_S+nL9p+8xfeU8N0L93f7w@mail.gmail.com>
In-Reply-To: <CAG_fn=WnxbcbjfKvRGen7fkKyx_9_S+nL9p+8xfeU8N0L93f7w@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 31 Jan 2023 20:01:17 +0100
Message-ID: <CA+fCnZdeQ1LqmzD=vCk6tG3GBydY1dwzNM94wZ_+oDcWTrY=Uw@mail.gmail.com>
Subject: Re: [PATCH 06/18] lib/stackdepot: annotate init and early init functions
To: Alexander Potapenko <glider@google.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=XvW89yFH;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::62b
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

On Tue, Jan 31, 2023 at 11:31 AM Alexander Potapenko <glider@google.com> wrote:
>
> On Mon, Jan 30, 2023 at 9:50 PM <andrey.konovalov@linux.dev> wrote:
> >
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Add comments to stack_depot_early_init and stack_depot_init to explain
> > certain parts of their implementation.
> >
> > Also add a pr_info message to stack_depot_early_init similar to the one
> > in stack_depot_init.
> >
> > Also move the scale variable in stack_depot_init to the scope where it
> > is being used.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Reviewed-by: Alexander Potapenko <glider@google.com>
> ...
> >
> > +/* Allocates a hash table via kvmalloc. Can be used after boot. */
> Nit: kvcalloc? (Doesn't really matter much)

Ah, right, forgot to fix this. I initially wanted to point out that
early init allocates in memblock and late init in slab or vmalloc but
then decided it's an unnecessary level of details. Will fix in v2.
Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdeQ1LqmzD%3DvCk6tG3GBydY1dwzNM94wZ_%2BoDcWTrY%3DUw%40mail.gmail.com.
