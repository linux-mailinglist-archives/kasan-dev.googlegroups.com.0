Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWX3YCSAMGQEOXXXG5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C6417355F3
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Jun 2023 13:37:00 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-4f86cb1e258sf738002e87.3
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Jun 2023 04:37:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1687174619; cv=pass;
        d=google.com; s=arc-20160816;
        b=J6Nd9xWzBtQXUvtspdSABsVPZykOBDdtWFvxORKvRQ7AE9FW64Khspa2pIEbC8ZylB
         choxi+vyhgfuexFaMTUfSxiuA9Xl/q5d7sovcfNRogMCkH5zBibVN6nGJkjTpg4LRHPX
         SNEGOZnFlGAQlwrr4yuzQJ5F1z6r7BYoNxbnh+IOwkLx+pVpCOfMvhjkD5sHb02XrPq2
         KKvBh6bL3OFuehEKkzJTN02PYlYwv60CpYmVbhTlhhEFh4U3lbfdpUL5WfNQ5r5epTM4
         zPTCYTE1BgNTB62Gfro9ogMOATmXzt6NXrGmhRhCBkQvHDgvxiCtNADp6ajY5Sp05gNE
         YvSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=csEHI+KWhWkXLs5cCYUg2SS1IUq6XbK507OEb6G4KOY=;
        b=AhtTeED76zMXQyvCoBNcNGeM8aT/ocfg3kFuToqHsGjOusTkmYd7UhkbI7iCfjSiq4
         OeLA00ovv354KLsSS1vhy2RRBhckcdDV0mIHjEZt9XBZJb08KkwjEsgVoC078U/CQq/w
         Lckx2tPVcrp9xMRjCG14AF+flmHkq0iPwTVTzFu6/nOuXSUQ/J4kCTiM811lR/43xO25
         o5NE4WkDcj1EWmNkvyFNMslLSzSXbYkr9heP6LGZjQtPKw2f9eMlnQStVXsGrdfHhDjm
         abzdlKirIz4YLxuo7z+YV3w2FXMleq8HyY8Uj14DUN8qWs8XX/6r+YnfjutZhUb4P9wk
         5GZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=GmVrGv8D;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1687174619; x=1689766619;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=csEHI+KWhWkXLs5cCYUg2SS1IUq6XbK507OEb6G4KOY=;
        b=AeyvCl/p9ZBaDugy9u9xFec5s+EubZpe6mYLU9XrogT4ZzQGL2fAoqhPmD4JwRXrbY
         FavxsapWCTJw1AOUv7kmktxOYQPSdvDlfgNosNFLtv7pWivEKG7NMrDKSeV59zMa63p8
         mSgUXzcJnZlHKVdMAcyKZ4ZSUf5QtTyGq8Fd7kBn6VTCxxT/jxFg4GjmvzS2J+aKJqXC
         iLPZ5Eh3IatXnzLQln9a07ai2aSpK0aOPmxxQdecuWIiNuiaHXfGY8sBucMaSl+a8KzM
         JTLTU+9/VPXNXhbVtwmQdpeRgsOFFXSm494iqF0Qg4I0Fom+l8cLI86Hh4976Gxw7QqN
         msAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1687174619; x=1689766619;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=csEHI+KWhWkXLs5cCYUg2SS1IUq6XbK507OEb6G4KOY=;
        b=YzWi4FnBDyZbKOsoU4NWtyb4tG0KDOnzJzTjbJXOMM/yBtPG2YKwbaellxeT8w/6Wz
         aj6G8xqdYUyLWvkckdf3kigsiQFjgnhv+9/A/QW1ym3gF0ytV92+lM9te5in5SjRlcOq
         dyY80PmpbRCdcrSwc7L2iJHlf1eA7xdc70DqMXzAkbBm5IpaDKpPoQJ6vKRkxa6WJxoh
         NZNOvnw9ibW4YLJ6Dwhu5vezAWpRRnvdeAeFhGAGgLjaNSZcswcFbbz/2d+U7p/lhhf7
         f3oCXofiRNv4Mk/hR7bAec325qGq++BY6EH5NqX+JlKChmV5DfHvcAH+CamrfIt8GsuQ
         fh1Q==
X-Gm-Message-State: AC+VfDwMXr9OzBaHB4XnIWoNQQmolp8ejFw1b0Pg7G8nneIQ/ZX5sRNa
	2Wp200cuJs/E1bAsoWLCxcA=
X-Google-Smtp-Source: ACHHUZ5BeS9JmCarM6i2Y9hs3b/wDXDwQnQ/hl1h7L3DpuERQF1B4BoKkPrasj0LyHucwn0N+gSn/A==
X-Received: by 2002:a19:441a:0:b0:4f5:bc19:68dd with SMTP id r26-20020a19441a000000b004f5bc1968ddmr5258451lfa.53.1687174618531;
        Mon, 19 Jun 2023 04:36:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:8c17:0:b0:4f8:46e8:2412 with SMTP id o23-20020a198c17000000b004f846e82412ls79425lfd.0.-pod-prod-08-eu;
 Mon, 19 Jun 2023 04:36:56 -0700 (PDT)
X-Received: by 2002:a19:7119:0:b0:4f7:6a7e:f078 with SMTP id m25-20020a197119000000b004f76a7ef078mr4666585lfc.50.1687174616774;
        Mon, 19 Jun 2023 04:36:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1687174616; cv=none;
        d=google.com; s=arc-20160816;
        b=KnoRmbCiavF+4v52ZaQGAc1US/vU+GpGcQLro8esvoMhRW+b5yBgWvmNVNTs5kHbue
         /IjDcdm90cRw7nr7g+G1DLeKyqU7E0HdlPPwqIy1VIHA1vYTFry0IUG/CvJkJ74QXJrT
         5eeRFJ1PBifj7TTDcxh6MNo3A6KMvbJS2RCJydh5zJ4teochyXVJlE4mdee97OOt3JRO
         W6HYIKLoTqme2EMeWqIYfFo6xZZqfBxNHbZ2a5XR+kOrvMHGT1j0RbsOaKWbpaidx0Nh
         P1FR/JJOhlfl+F+NxPIucRdRWbBhoVbBulybEXz2tzAS7V2tu+XdaUBXSkSHmKshbRb3
         zlfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FvbuaaSlDBqWb5lPKsIhoBijmFdvxXqOiBhjtzjptTs=;
        b=XALUHzv88DDlylg0lvtYghfrB1iItVSYOMe+TJX95lCF5oT97CpOo0t7Z6IuwZRL0A
         w+WqNkO5vUlY5a5hMIkCE1w0YyPbbwYSBAIszPJ9ewZu3vyoP2BSSjHwViUv/8dSGpya
         XXmUYSoI+FxgqDueHmg74gGnLuz3eFGfG6FaKOGvyXxDbflXgGCVnbWHvOEcOV7OMomC
         UP7AFSmogVuhZXJqs8cB4xeZ9/EJG147nF5jFEOaUpHpwp5XYdWQvkettGDLcjiXl8zj
         EoEiJTJ6LbuvzDayi0aRkTasz74jIEv/wxWm4xThfjFVBiG8SN/ofABH+wjTBDmjC+iw
         ECZw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=GmVrGv8D;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x133.google.com (mail-lf1-x133.google.com. [2a00:1450:4864:20::133])
        by gmr-mx.google.com with ESMTPS id v14-20020a05651203ae00b004f8576a0334si491002lfp.1.2023.06.19.04.36.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Jun 2023 04:36:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::133 as permitted sender) client-ip=2a00:1450:4864:20::133;
Received: by mail-lf1-x133.google.com with SMTP id 2adb3069b0e04-4f86bc35f13so1698305e87.1
        for <kasan-dev@googlegroups.com>; Mon, 19 Jun 2023 04:36:56 -0700 (PDT)
X-Received: by 2002:a19:5f07:0:b0:4dd:9f86:859d with SMTP id
 t7-20020a195f07000000b004dd9f86859dmr5082021lfb.13.1687174616231; Mon, 19 Jun
 2023 04:36:56 -0700 (PDT)
MIME-Version: 1.0
References: <20230619101224.22978-1-chanho.min@lge.com> <CACT4Y+Zn49-6R00buq-y_H0qs=4gBh6PBsJDFBptL8=h6GPQYA@mail.gmail.com>
In-Reply-To: <CACT4Y+Zn49-6R00buq-y_H0qs=4gBh6PBsJDFBptL8=h6GPQYA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 19 Jun 2023 13:36:19 +0200
Message-ID: <CANpmjNMSfVeDa-YC-RQcZ-V=wvHGi43xvXSvaR0GQkEP0OOmOQ@mail.gmail.com>
Subject: Re: [PATCH] kasan: fix mention for KASAN_HW_TAGS
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Chanho Min <chanho.min@lge.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, gunho.lee@lge.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=GmVrGv8D;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::133 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, 19 Jun 2023 at 12:15, Dmitry Vyukov <dvyukov@google.com> wrote:
> On Mon, 19 Jun 2023 at 12:12, Chanho Min <chanho.min@lge.com> wrote:
> >
> > This patch removes description of the KASAN_HW_TAGS's memory consumption.
> > KASAN_HW_TAGS does not set 1/32nd shadow memory.
>
> The hardware still allocates/uses shadow in MTE.
> Though, it may be 1/16-th, not sure.

I think the point is that it depends on the hardware implementation of
MTE. There are a range of possibilities, but enabling KASAN_HW_TAGS
doesn't consume any extra memory for tags itself if the hardware has
to enable MTE and provision tag space via firmware to begin with.

> > Signed-off-by: Chanho Min <chanho.min@lge.com>

I think you just have to be a bit clearer in the commit description,
just briefly mentioning how/where the tag space is allocated in
hardware that do support MTE. Then removing this line is probably
fair, if KASAN_HW_TAGS isn't the direct reason for tag memory being
allocated.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMSfVeDa-YC-RQcZ-V%3DwvHGi43xvXSvaR0GQkEP0OOmOQ%40mail.gmail.com.
