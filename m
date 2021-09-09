Return-Path: <kasan-dev+bncBCK2XL5R4APRBX6G42EQMGQE2S5B2FY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 8728A40454C
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Sep 2021 08:02:07 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id y13-20020adfe6cd000000b00159694c711dsf147728wrm.17
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Sep 2021 23:02:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631167327; cv=pass;
        d=google.com; s=arc-20160816;
        b=DcHU+g1wm0qKmxsJFmnDFg8ZCsuUXGX63IeUoXw2jvea5OuRuQWOAqEstgPzBFiVy1
         1co1oBNpmWaZUbJ/smkEkSkBrh1g6/fUXSIkyFpiMQbyfRYUxI+rd/n/Jpw5L+wpNdJO
         Im5yaABIQnyXUos3U8byq/+6MlAgR9sZi2lK5o+CcpMp8zpRP9FCXwnHo0ZuJIOwHYAc
         T8qrey5en0RFgUMkz2ydaBmMNPwZ2HT5yCopoKG5tyoi5ZloKTafPR74RdkokQwgB5ub
         leVYwO/a2XU+j9BILn1MOv7/5WCKHmHBfzH1yJB4keqRewKJVTZGJAZ/DL0nlEWxjdyr
         2Cjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=pUg2oTZj1qqdDjQ0mgavq44rbbeBauZ3kmQ82UavH5M=;
        b=v8ZhnaPuBzwfFaBVZ9C40z0t2AunbpK0cTKhQNa9BuDVeCJq8n8IKO8MZdQ9/oUGNh
         xy+YpDpL+e1xjgQr5vTrOdh7Gvjyyb3x3jiTORcTRS4oKN1+rA2Jd+0BRLhC0+enHV3G
         +akn0ALw3a0IrXJ2CC645oHQVaEZKZTiLlR31n2erepPC14RzD6raFte2oon8+ASr4Bn
         W2suoCbuy8XVDIQOUBuINZGWGSg+T3m5XpMXvo3XwgODAi5CZ6WDeHK1NFxNELQBUR/7
         1EXaDRhWHUzcPQryw3nGvnP6o8o6OO1+fzpcy1uRVswr0GVkpZh//IxtqLY7aTD7qsmk
         s8PQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=m7G+7uoz;
       spf=pass (google.com: best guess record for domain of batv+ab606af41e2b6213a0ed+6591+infradead.org+hch@casper.srs.infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=BATV+ab606af41e2b6213a0ed+6591+infradead.org+hch@casper.srs.infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pUg2oTZj1qqdDjQ0mgavq44rbbeBauZ3kmQ82UavH5M=;
        b=R116nftufRmmbIRwduMQprBtNbMvIgGUG1c5MSU1/bPGOSdZvETFh0Bt670/gdAaZ7
         Qa/hNuOH07+irGLsEZo6lWB7aKaUftuyCwgOQ7x8Xa3BUXqP2qA7OyFKMnCvf/NEM26b
         gqd6BxrWUCHbDJRYM72bBkBJf5GGRchRmiQq3sSrAhzjU768Sf28dMD6lJNwFccoDYws
         m2HRdRgS179KPcDiIRwoyNwf1vPaCCuxcEdda1B/8iRIbXq/HXBns4BbUMU8Ls35Pb36
         bGgmxWMOIhqXWlsQluy8c0PgLF7ByOUGXlXmfMgAW2VyK4n77KkEzZ80kgD4ae8CaDTW
         zg7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pUg2oTZj1qqdDjQ0mgavq44rbbeBauZ3kmQ82UavH5M=;
        b=1+mG5mFl0Kco6bu/VvfpmbC4E/6PP8naG4vTid8DgJ//oR5tIgMMhJi6RZeklWkYve
         qEU4HZWF1G39ccWAmsxKC1JvdPXT6nD8cpvve/ZKHG/e2f9blclZL71MnlvqugwZSMJt
         EpbY7VqZDwujdhSBepkNuROrBWarZ0FN4PAzhmYVBl2u1I/DpSCsvdjsssNOckhXR0Pg
         x22IIWFef9gI6L8DNh7BmosiWZ5l5fMHNPffj7NHdwaebFsPgtqlP+Kxunq6Xcb5iqOB
         NU3bi7Ll5iqFaFS9RWD9QT+SRl0LEHPZgUIEzVPm5FG6vQjx+BMKrE0nOp3I6lHOgEhV
         X7MA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532xYF3XyWcBce6eTCamsww+N9J1pdex88/piS2Y3dE1bjCNC8iG
	IEFsXT/5llO44Ul4Aamd5as=
X-Google-Smtp-Source: ABdhPJzD7TO8RT/gd5sARWSYFZjnw0mrXTU9hD55PGtHjEFgxVMMs/UU0LkgxTs7JaOs8855p5+XvQ==
X-Received: by 2002:adf:c18a:: with SMTP id x10mr1392876wre.302.1631167327275;
        Wed, 08 Sep 2021 23:02:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c2b2:: with SMTP id c18ls309400wmk.2.gmail; Wed, 08 Sep
 2021 23:02:06 -0700 (PDT)
X-Received: by 2002:a1c:9a0e:: with SMTP id c14mr1081798wme.119.1631167326287;
        Wed, 08 Sep 2021 23:02:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631167326; cv=none;
        d=google.com; s=arc-20160816;
        b=1E1SCnfGC5MRVSiNl91vCDtrA+m2etnngR98/+H2/Q4tIR47XBeiAQsn+wIJXXXTja
         nKhcBjQCKr6s3cVO4ZnEuy6u4s+VrqI6SKzheEtFoLNT7OLWU8mh5EKC7O7gfa1lFyGH
         +lOVxjsKvNggRMRrRfGgdOt42z7KHBdPvEFldeQvxkgzGTemMOva/rQbuI/ZXot3rmzp
         Q7/MmagVO3fQ6x1LeTVnr06iQ1KRNdv7068AX4hQmwjFc6Lnko9yL6wO+tBH2sNU7qC5
         uyvKu6mf9ZQ1s0U9xmr2appZbqtGeNJW8zObvTOpiBGKGemEWSBi8Cz/3nUhVh2xBjjZ
         +IcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=EmyOmO4OA1vu17LO++qu8IgyrFImV3HoLCHV1XeAKXU=;
        b=nDSFzyfak5GR+xvvVu0y+5NFYx21X4q60ZjhK6nnHLLfiI4ozbyqymiTV1/q1zcHJh
         i8wtdkJh9+Ye2nAyhDuQK8bmT/Wmt3MlAGTfagKZGApD1KNXCac0nyOFanLQeH2qefFA
         rpwqeX2pl+4zsflgz8WmHG0RP+khNl1+jFlq16aNT30RP8ZpOWH84yk1N9KjdjW4lHdL
         /yaAZ5ZHPLymywUHSlW8TNceMn+Gr/dLz+UkY918IPxR8KOizl+eUZ1pEMBrgGsEi8p5
         HvOZ4iM/gJbMt6XNACvemUxgnr1sEIHVjZzt7bpDMEecUSZKChzSKGbh1w0tjxNCZAFI
         WZgA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=m7G+7uoz;
       spf=pass (google.com: best guess record for domain of batv+ab606af41e2b6213a0ed+6591+infradead.org+hch@casper.srs.infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=BATV+ab606af41e2b6213a0ed+6591+infradead.org+hch@casper.srs.infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id t16si39126wrx.3.2021.09.08.23.02.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 08 Sep 2021 23:02:06 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of batv+ab606af41e2b6213a0ed+6591+infradead.org+hch@casper.srs.infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from hch by casper.infradead.org with local (Exim 4.94.2 #2 (Red Hat Linux))
	id 1mOD4f-009WcX-Hg; Thu, 09 Sep 2021 05:58:27 +0000
Date: Thu, 9 Sep 2021 06:58:13 +0100
From: Christoph Hellwig <hch@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Guenter Roeck <linux@roeck-us.net>,
	Nathan Chancellor <nathan@kernel.org>,
	Arnd Bergmann <arnd@kernel.org>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	llvm@lists.linux.dev, Nick Desaulniers <ndesaulniers@google.com>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>, linux-riscv@lists.infradead.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>, kasan-dev@googlegroups.com,
	Christian =?unknown-8bit?B?S8O2bmln?= <christian.koenig@amd.com>,
	"Pan, Xinhui" <Xinhui.Pan@amd.com>, amd-gfx@lists.freedesktop.org
Subject: Re: [PATCH] Enable '-Werror' by default for all kernel builds
Message-ID: <YTmidYBdchAv/vpS@infradead.org>
References: <20210906142615.GA1917503@roeck-us.net>
 <CAHk-=wgjTePY1v_D-jszz4NrpTso0CdvB9PcdroPS=TNU1oZMQ@mail.gmail.com>
 <YTbOs13waorzamZ6@Ryzen-9-3900X.localdomain>
 <CAK8P3a3_Tdc-XVPXrJ69j3S9048uzmVJGrNcvi0T6yr6OrHkPw@mail.gmail.com>
 <YTkjJPCdR1VGaaVm@archlinux-ax161>
 <75a10e8b-9f11-64c4-460b-9f3ac09965e2@roeck-us.net>
 <YTkyIAevt7XOd+8j@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <YTkyIAevt7XOd+8j@elver.google.com>
X-SRS-Rewrite: SMTP reverse-path rewritten from <hch@infradead.org> by casper.infradead.org. See http://www.infradead.org/rpr.html
X-Original-Sender: hch@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=m7G+7uoz;
       spf=pass (google.com: best guess record for domain of
 batv+ab606af41e2b6213a0ed+6591+infradead.org+hch@casper.srs.infradead.org
 designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=BATV+ab606af41e2b6213a0ed+6591+infradead.org+hch@casper.srs.infradead.org
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

On Wed, Sep 08, 2021 at 11:58:56PM +0200, Marco Elver wrote:
> It'd be good to avoid. It has helped uncover build issues with KASAN in
> the past. Or at least make it dependent on the problematic architecture.
> For example if arm is a problem, something like this:

I'm also seeing quite a few stack size warnings with KASAN on x86_64
without COMPILT_TEST using gcc 10.2.1 from Debian.  In fact there are a
few warnings without KASAN, but with KASAN there are a lot more.
I'll try to find some time to dig into them.

While we're at it, with -Werror something like this is really futile:

drivers/gpu/drm/amd/amdgpu/amdgpu_object.c: In function =E2=80=98amdgpu_bo_=
support_uswc=E2=80=99:
drivers/gpu/drm/amd/amdgpu/amdgpu_object.c:493:2: warning: #warning
Please enable CONFIG_MTRR and CONFIG_X86_PAT for better performance thanks =
to write-combining [-Wcpp
  493 | #warning Please enable CONFIG_MTRR and CONFIG_X86_PAT for better pe=
rformance \
      |  ^~~~~~~

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/YTmidYBdchAv/vpS%40infradead.org.
