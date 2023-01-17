Return-Path: <kasan-dev+bncBCQJP74GSUDRBNP7TOPAMGQESFE55ZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id D6FE566E765
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Jan 2023 21:06:14 +0100 (CET)
Received: by mail-il1-x140.google.com with SMTP id l14-20020a056e02066e00b0030bff7a1841sf24018562ilt.23
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Jan 2023 12:06:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673985973; cv=pass;
        d=google.com; s=arc-20160816;
        b=0YSW+E7EBMjZeZSIl3BiHhw7rWUjfod1yG0PAeRByxqM9h9Q7jd2EmyuTQL642oeyj
         SGfDt+6dqlMLMowUX/4vRuut/19aJPgQ0CKfSaldc867HWOwV4HK721lmtUUIVdTTugp
         hUA9tmANJcmqrQnZ8BrpdARHIFJNWoK2e/Mgpg8w2cEcxQOl0+X6csg6bq2Bqju6h9n0
         aQffqXX1phfS3nMKAN1/qZibJR2FusiH/QGvudDAqBGIrRDe76S/qhJyhxlF6R7Zfz9B
         jDFesVk0KUzXmMyO2utz02EthM1b7sFbpELDNA7AN/+nNMyA59emGP9Z5pHlm1xUW44C
         cGkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=gqBioSP/CuQK5yrRBiKisiFTdWGoHx9Lb9oIhnrAs90=;
        b=mJuxQV4rlQ1SU9hZyIgjbAzZ1VnTnspNZKccszeExLv4mqS35arWYKytLq4SYgolt6
         C1FNYWqmTPA9CtEq9HtfFOT3oTRlW3/yy0JeZHkID/l8gcp95WdoNGRWwFp/34RCUuAQ
         mM2h1y3SaLEE19zJe4S411BPYX5GaUNOc2DS9pNNRS84tICYbYy1cBQdBSAj05EZC+QP
         5T/klsBB+u98KOcHrYbN2VzpYmb3w9cE53v1a1LWuVTHQzH9kQnumBEw043VON+6x5Pp
         qGm3GU+BQZkln8WXK4IAXhBTRRPeLbDGx8Uf4nS1Z1v98JaMLo9XQNB1B+FP/L+dO9oC
         /JBg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.219.44 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gqBioSP/CuQK5yrRBiKisiFTdWGoHx9Lb9oIhnrAs90=;
        b=os2ScNY0zQ07geJou6Gdmp3f3v6yQlptJY8Bp5Tz/HzlA2T9eSSlPWxlVhTlWeVtKZ
         q1u/S+jTzq7PniWn6rO+gvNfiOe3KlxiJvXoMp9sRxjcAFFADmpqCBoqokiR0OTjm8AT
         StGAqaYSjXRTN+R0Uzr76XebKxnaMXshR1IaWdQFHn4FuNI2anAYesZ8AdO2G2lypylb
         2kK3HLBAJGiHK2DizuKfeCXINbONN1WkivpbjqssHAKWk3Nz8mDuQcKc1ZiQ7z5iK/nR
         Ff+UiTWVXZQSijjYha3qIGTxIkyAPzr31y6NOxAAY9Fkx0tMZT2CkpfgBHgIzulIp1Kv
         ZWzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gqBioSP/CuQK5yrRBiKisiFTdWGoHx9Lb9oIhnrAs90=;
        b=lxZu/v9gE9trBLBXRYSaqAx6LWkUJMcamDP0HDQQhz4/POO3kZgTRgeUtlrSKw0w1Q
         yiNy9NFh+BPITLoelNCQH89KPgyD+54O2Nw0wQgvA2eDcTdA6H56fGR7S4HvTm0U7zbh
         paigBaJR5N1cYyNbE1IqmEGjMrDjmZOCpmtv+IkDv4ZMJaKFX7x4znvQnBLN3GQyyIgP
         IAITmFrSfdfat5gIYBMDZII21aCzU4QnOsnH5/z2EOToMSs5jnrPE9jkkrVMkGWiTpdK
         cQ9CwzHNhjOOF5ZD/3zbdQ5eFb5vQtL0IBn2/dmr/u8ecfuF8K+14bysybKMiXW8T3Ls
         +blA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2krM7a5lMHpvH4K8cIn/7L/NWFlrQhdtMc+SjN+Mz3PiEXfKnzVx
	5tj3+OwFHxPhXROm8z+Ip5U=
X-Google-Smtp-Source: AMrXdXu41F+SDX/9sF/hwxtNfaMfoYbKMBFxupDdE8Ed81Odk7PpbfCgp5VOQ/c/PRkPnGUhVHWXGA==
X-Received: by 2002:a5e:9505:0:b0:704:aa70:2b13 with SMTP id r5-20020a5e9505000000b00704aa702b13mr310206ioj.91.1673985973652;
        Tue, 17 Jan 2023 12:06:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:4917:0:b0:6da:9bee:b03e with SMTP id u23-20020a6b4917000000b006da9beeb03els3047744iob.2.-pod-prod-gmail;
 Tue, 17 Jan 2023 12:06:13 -0800 (PST)
X-Received: by 2002:a05:6602:5d9:b0:6e2:fd23:821b with SMTP id w25-20020a05660205d900b006e2fd23821bmr3171055iox.3.1673985973099;
        Tue, 17 Jan 2023 12:06:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673985973; cv=none;
        d=google.com; s=arc-20160816;
        b=egxBjHWImWL2hicpYqei9QZQilTWo8q/Ko3g0lNAaJGMuwBeA6XJgVL3Eg/jDIBIbn
         Ym4umnsnOu65fDNDAhXnaZYGSYpkVOEg5uK6QMWh8StVhnL6uaLiCTvjcd+8J/TVOe1G
         31RtJ/RbldYLJMGRC7KON2LIAdBerfy6AVYSkQbRtrMUI7qxsphUo7gkRlJyIhcgOqGm
         ylrQQrqSvbudKAg2gOyRj+MLNWqq9QyTQWi0HiQ+gFFWkHAG19hOONQE/HBXK2Zl+ZR6
         Cl+l8LksHi18GEvk8OTEWYGvew1eM/dO8GvSgrCOGVNAgO0pNyoGl1tNHbnwhaLfy6Pb
         lt9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version;
        bh=3xoeiV+nYOsKZ3P5r1QIbmJ251MgYmk7NsIx6imHg00=;
        b=GajPgI/6775warNgw9guODBc3HSXShkERhioNZ7dZ+F2BVax99Cj8Ohb9L+ZLHvXXv
         k+2+z+Q02IaNhczhvBHV5WRUgYUyxjsVSaYtxiYnB+tqaJIAn5acc96Z/Rfobt9lroTO
         iVaFbfU8eP04o+niJ+tfo6Iu2Exkon81Upg9L7QDHqhr9sGHFO3gbDr83Gg65uJ5UoBz
         zsJWynMWZmKhYmnXBtm91XVtDzCCosoqkf1EqkY7Fr/M+k4ZDlwHxOWTuYgbpsX5Cgh8
         uhinbkretOkI17sBHxB1E8+q3U3Twy0oPg4Ay+Zhh7PNBvzyXLaxytF24l6+whKDSTYA
         MoQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.219.44 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
Received: from mail-qv1-f44.google.com (mail-qv1-f44.google.com. [209.85.219.44])
        by gmr-mx.google.com with ESMTPS id k13-20020a0566022d8d00b007048277b640si978239iow.3.2023.01.17.12.06.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 17 Jan 2023 12:06:12 -0800 (PST)
Received-SPF: pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.219.44 as permitted sender) client-ip=209.85.219.44;
Received: by mail-qv1-f44.google.com with SMTP id k12so1493303qvj.5
        for <kasan-dev@googlegroups.com>; Tue, 17 Jan 2023 12:06:12 -0800 (PST)
X-Received: by 2002:a0c:f608:0:b0:535:35ce:7906 with SMTP id r8-20020a0cf608000000b0053535ce7906mr2410457qvm.40.1673985971994;
        Tue, 17 Jan 2023 12:06:11 -0800 (PST)
Received: from mail-yb1-f169.google.com (mail-yb1-f169.google.com. [209.85.219.169])
        by smtp.gmail.com with ESMTPSA id cx15-20020a05620a51cf00b00704c62638f4sm20448581qkb.89.2023.01.17.12.06.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 17 Jan 2023 12:06:11 -0800 (PST)
Received: by mail-yb1-f169.google.com with SMTP id 66so305846yba.4
        for <kasan-dev@googlegroups.com>; Tue, 17 Jan 2023 12:06:10 -0800 (PST)
X-Received: by 2002:a25:9012:0:b0:7b8:a0b8:f7ec with SMTP id
 s18-20020a259012000000b007b8a0b8f7ecmr700718ybl.36.1673985970579; Tue, 17 Jan
 2023 12:06:10 -0800 (PST)
MIME-Version: 1.0
References: <CAHk-=wgf929uGOVpiWALPyC7pv_9KbwB2EAvQ3C4woshZZ5zqQ@mail.gmail.com>
 <20221227082932.798359-1-geert@linux-m68k.org> <alpine.DEB.2.22.394.2212270933530.311423@ramsan.of.borg>
 <c05bee5d-0d69-289b-fe4b-98f4cd31a4f5@physik.fu-berlin.de>
 <CAMuHMdXNJveXHeS=g-aHbnxtyACxq1wCeaTg8LbpYqJTCqk86g@mail.gmail.com>
 <3800eaa8-a4da-b2f0-da31-6627176cb92e@physik.fu-berlin.de>
 <CAMuHMdWbBRkhecrqcir92TgZnffMe8ku2t7PcVLqA6e6F-j=iw@mail.gmail.com> <429140e0-72fe-c91c-53bc-124d33ab5ffa@physik.fu-berlin.de>
In-Reply-To: <429140e0-72fe-c91c-53bc-124d33ab5ffa@physik.fu-berlin.de>
From: Geert Uytterhoeven <geert@linux-m68k.org>
Date: Tue, 17 Jan 2023 21:05:58 +0100
X-Gmail-Original-Message-ID: <CAMuHMdWpHSsAB3WosyCVgS6+t4pU35Xfj3tjmdCDoyS2QkS7iw@mail.gmail.com>
Message-ID: <CAMuHMdWpHSsAB3WosyCVgS6+t4pU35Xfj3tjmdCDoyS2QkS7iw@mail.gmail.com>
Subject: Re: Calculating array sizes in C - was: Re: Build regressions/improvements
 in v6.2-rc1
To: John Paul Adrian Glaubitz <glaubitz@physik.fu-berlin.de>
Cc: linux-kernel@vger.kernel.org, amd-gfx@lists.freedesktop.org, 
	linux-arm-kernel@lists.infradead.org, linux-media@vger.kernel.org, 
	linux-wireless@vger.kernel.org, linux-mips@vger.kernel.org, 
	linux-sh@vger.kernel.org, linux-f2fs-devel@lists.sourceforge.net, 
	linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com, 
	linux-xtensa@linux-xtensa.org, 
	Michael Karcher <kernel@mkarcher.dialup.fu-berlin.de>, Arnd Bergmann <arnd@arndb.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: geert@linux-m68k.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.219.44
 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
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

Hi Adrian,

On Tue, Jan 17, 2023 at 6:06 PM John Paul Adrian Glaubitz
<glaubitz@physik.fu-berlin.de> wrote:
> On 1/17/23 18:01, Geert Uytterhoeven wrote:
> > The issue is that some of the parameters are not arrays, but
> > NULL. E.g.:
> >
> > arch/sh/kernel/cpu/sh2/setup-sh7619.c:static
> > DECLARE_INTC_DESC(intc_desc, "sh7619", vectors, NULL,
> > arch/sh/kernel/cpu/sh2/setup-sh7619.c-                   NULL,
> > prio_registers, NULL);
>
> Isn't this supposed to be caught by this check:
>
>         a, __same_type(a, NULL)
>
> ?

Yeah, but gcc thinks it is smarter than us...
Probably it drops the test, assuming UB cannot happen.

Gr{oetje,eeting}s,

                        Geert

--
Geert Uytterhoeven -- There's lots of Linux beyond ia32 -- geert@linux-m68k.org

In personal conversations with technical people, I call myself a hacker. But
when I'm talking to journalists I just say "programmer" or something like that.
                                -- Linus Torvalds

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMuHMdWpHSsAB3WosyCVgS6%2Bt4pU35Xfj3tjmdCDoyS2QkS7iw%40mail.gmail.com.
