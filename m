Return-Path: <kasan-dev+bncBCCMH5WKTMGRBYU2R6SQMGQEX64F5EQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id C76A7746AE1
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Jul 2023 09:42:27 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-635e0889cc5sf54492396d6.2
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Jul 2023 00:42:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1688456547; cv=pass;
        d=google.com; s=arc-20160816;
        b=YtaTvuhUEaR/nrDJgGamL/ZL5uUMSNexq4fQCE5MZZyx+rPEzaxgTB3SPqagR5gpFJ
         F0/PvLg180BRZz6sSaP9Ua18BBmRXFrAkEFG5qJ0Lwey/fllP+GdLzbReTJRgy85Htkh
         HMqawlU59cWg7WEgzs8KOhMK62ARkr2xDngL8lAQIgCelgvy5XWILyLok3DEdiIzdxNg
         oGKfTt/kOnehroBTunYq7kaHuUZ3tIkbjN//Zr/od3Kkh7IZ2VQq8hs2pvplRSsjy29y
         fX9JMyXCVylF3r/OL2E4ZziRxpFT4RDUUU3MQvptMLQvxO9g1uwqD0Fj6No4cZk/oGvB
         gk0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9WyLLOsQtlyPOzX/tCvBltJFC/4L3ecm+xK0jFqLJNU=;
        fh=qdq4djkKZxfbdpaMcmJ8ruwfNgqXVyBD9QTc06yhdE0=;
        b=A8y5dd3ffeBjJP3uniOc3SImgDIqRmqDSbePdMHWmjjhiocC1ySL2nE9o45o//hPLM
         dPM4uRYCjgceKfl5l+S2VIJ2oQqUhqPUrkESyAQCCBl5ywqFy3CHH76hhjSqZdxmXuVr
         1nRtwJm1z3dKkzvh/UNELzZD7VntHe5YD6b1bAYoQ5kEHVFFG3z8tDu5TXUJf0iCqdxa
         f/IyYe03KUKlxm8UCV+sxtoXFh5qGK03jzgRdQ8zkXw0TWeR6E/qlwyHc0PyawXYvuLh
         uB3ACYvW1MK0JgAUt7JQ56dy/FaK+WQXXM0M/s3xZk0zu8BSLoLvChYVhYXmoBmBn1t8
         PeRw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=mAC65k4g;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d36 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1688456547; x=1691048547;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9WyLLOsQtlyPOzX/tCvBltJFC/4L3ecm+xK0jFqLJNU=;
        b=OyoFYqroHJ6Jo7kY5FpWX+XPKwpXtnt1UsPf0AVjWliZNlwuHw4WE2bxAiyABq0dn4
         HfrkQLqT99pU26jeFxTjTxiShEwA+PPTibTcPWCHqJwC5+cSSB4TNywvXtLIJHU6lLna
         9259fkEmRHDxY5MuZEQJoVblvsWFyj2dppnYNEjj9329WzchFDVosh9FaI16UKRjiemZ
         MmA7+cB964SjAupPE9jZkxjF6bSn3zTxUjih0nLKdoJuibb1PELkv2DLNpS99bzTij+G
         4rerSk6ZSFJeveLkO3RoXZjF5qD75I7Gym04gJBIEs+tW70cIet49EfvuJ+4F03ZnPIX
         263w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1688456547; x=1691048547;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=9WyLLOsQtlyPOzX/tCvBltJFC/4L3ecm+xK0jFqLJNU=;
        b=DewJ7sY5w0jQF9qxxXDqyTEh1EAo5ddVNo68XHL9uyfo8qgwILPtTawVwgtfQbbsfg
         4yC0SmROhQPHqLYZlbYYzgSCkXImVcWs1xngHQnXNrsQNzjVrlOpOrV62HR8ywlL4OfO
         j3+oKtxQwakkDhbZZfv8q+33vkmyLn31r1UYO9IEBs8Og3NU4SchmJTgku+sWUjBo4Hp
         mtZr3V8ECUeJR1BKJV6YlI1FUgzfNxWZWHEaRll8sZ62I/D2fgLGIQ04+r+R477CpxQE
         ZUcmumnDrPtJIfgdLHW0OQm4W1F16qHMh2QA8ZpIfsC0G/BpZ+L8T6nFvpEktw1nMOp0
         FZpQ==
X-Gm-Message-State: ABy/qLYp7pYKI/UJ3lsz/YfZuUQXVlAIZjspsl3evmde6Xny48Po3sts
	EjlL0wckyuZf8nQ6cYlW1dA=
X-Google-Smtp-Source: APBJJlFbrt+wpURrW5YBT4EH79w4qfsxE+iVB3cyH9RiF06GdbBpzeG+ozHjTi5EKgFM3bFD+54IyA==
X-Received: by 2002:ad4:5811:0:b0:5ef:8004:e0b4 with SMTP id dd17-20020ad45811000000b005ef8004e0b4mr10098381qvb.48.1688456546565;
        Tue, 04 Jul 2023 00:42:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:9d0b:0:b0:635:c4b2:5800 with SMTP id m11-20020a0c9d0b000000b00635c4b25800ls2374015qvf.0.-pod-prod-02-us;
 Tue, 04 Jul 2023 00:42:26 -0700 (PDT)
X-Received: by 2002:a37:f611:0:b0:767:2198:b52b with SMTP id y17-20020a37f611000000b007672198b52bmr10593529qkj.78.1688456545956;
        Tue, 04 Jul 2023 00:42:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1688456545; cv=none;
        d=google.com; s=arc-20160816;
        b=XR20RRIEcGnrr7MlgrItCGSRlS5h2Bk0nH+OK3Qkhb8oa1XG9DXgxM/2J+uwUqE/TU
         c1onY9H1BCy1WPEmp+aI2dKG0t0rQEKiR9cgYJ88M+4jX4D89L1hHp9lmh9fWyofenDD
         BtqZkHokGgEg+vDDvAjVn7UGxWLzRgEYg+B+UvB3YS36e9nD7d9Vw36/zeogDgKV1NB6
         +UAc2SIayhMVLhP0lW44y7Bv/kPKhMMD6xRxwCRt0DKWnRWU/Lp6CqrMrPuVipucpWfY
         aOoG+SF4VYI+puTwjhgLFyDWMTiN/3BtLrwDNC1L+gGFib3HJasthCh9tDvNVhH7EVxV
         Q8ZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=DG4xU/vLluE9GD6s3lDFIOyk5s/wLag9r93/fpgmZeI=;
        fh=vhYikPIY+N1YVdWM/QFvuw1Zy7m9Vcrs+P61H9MG+04=;
        b=E80ymnADVyu3pM2IsIeNcopDKQ3TiegIieSqFfFK+lxEc6TMWusFqUH0iuPv1vZgFF
         sh4Rb10+EE0ua3pOnCz7yWQJsvQk1drjpbZvxZgxsdJ1WzYFsnaD0kBATVfSqRD7vXDw
         3r1cHuYoAi143b0Y28rB2bVoTtwlXgN97KFSBe+aTU507IycCRVj3UbLgiDPprKIs5kP
         IVinG5uHjnlc+SIVidOCetAw6JPkQmIiE7ctWxz/Z3CGz5ehcqqqWMY3XaKcwu+62h2U
         VMrxCokPL0QIWnqeWYmmmLhFmZaWHKS47Oz5QkpCrRKVajPzZVIloWXi3qgGsAP28mQg
         qD4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=mAC65k4g;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d36 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd36.google.com (mail-io1-xd36.google.com. [2607:f8b0:4864:20::d36])
        by gmr-mx.google.com with ESMTPS id bm37-20020a05620a19a500b0076631946c94si565007qkb.6.2023.07.04.00.42.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Jul 2023 00:42:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d36 as permitted sender) client-ip=2607:f8b0:4864:20::d36;
Received: by mail-io1-xd36.google.com with SMTP id ca18e2360f4ac-78363cc070aso260764039f.1
        for <kasan-dev@googlegroups.com>; Tue, 04 Jul 2023 00:42:25 -0700 (PDT)
X-Received: by 2002:a6b:e718:0:b0:785:cd37:26a6 with SMTP id
 b24-20020a6be718000000b00785cd3726a6mr13895910ioh.3.1688456545302; Tue, 04
 Jul 2023 00:42:25 -0700 (PDT)
MIME-Version: 1.0
References: <20230628154714.GB22090@willie-the-truck>
In-Reply-To: <20230628154714.GB22090@willie-the-truck>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 4 Jul 2023 09:41:45 +0200
Message-ID: <CAG_fn=UW0pX5+kRqqr9LH5wYbvA=1rABW8K+trGd-Jt8aynTww@mail.gmail.com>
Subject: Re: HW-KASAN and CONFIG_SLUB_DEBUG_ON=y screams about redzone corruption
To: Will Deacon <will@kernel.org>
Cc: catalin.marinas@arm.com, ryabinin.a.a@gmail.com, andreyknvl@gmail.com, 
	pcc@google.com, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arm-kernel@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=mAC65k4g;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d36 as
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

On Wed, Jun 28, 2023 at 5:47=E2=80=AFPM Will Deacon <will@kernel.org> wrote=
:
>
> Hi memory tagging folks,
>
> While debugging something else, I ended up running v6.4 on an arm64 (v9)
> fastmodel with both CONFIG_SLUB_DEBUG_ON=3Dy and CONFIG_KASAN_HW_TAGS=3Dy=
.
> This makes the system pretty unusable, as I see a tonne of kmalloc
> Redzone corruption messages pretty much straight out of startup (example
> below).
>
> Please can you take a look?
>
> Cheers,
Does the problem reproduce with CONFIG_KASAN_SW_TAGS?
Also, any chance you could share the file:line info for the stack trace bel=
ow?

I myself haven't expected KASAN to work together with SLUB_DEBUG...

>
> Will
>
> --->8
>
> [    0.000000] SLUB: HWalign=3D64, Order=3D0-3, MinObjects=3D0, CPUs=3D8,=
 Nodes=3D1
> [    0.000000] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D
> [    0.000000] BUG kmalloc-128 (Not tainted): kmalloc Redzone overwritten
> [    0.000000] ----------------------------------------------------------=
-------------------
> [    0.000000]
> [    0.000000] 0xffff00080001a9b0-0xf1ff00080001a9ff @offset=3D2480. Firs=
t byte 0x0 instead of 0xcc
> [    0.000000] Allocated in apply_wqattrs_prepare+0x90/0x2a4 age=3D0 cpu=
=3D0 pid=3D0
> [    0.000000]  kmalloc_trace+0x34/0x6c
> [    0.000000]  apply_wqattrs_prepare+0x90/0x2a4
> [    0.000000]  apply_workqueue_attrs+0x5c/0xb4
> [    0.000000]  alloc_workqueue+0x368/0x4f8
> [    0.000000]  workqueue_init_early+0x2e8/0x3ac
> [    0.000000]  start_kernel+0x168/0x394
> [    0.000000]  __primary_switched+0xbc/0xc4
> [    0.000000] Slab 0xfffffc0020000680 objects=3D21 used=3D8 fp=3D0xffff0=
0080001ac80 flags=3D0xbfffc0000010200(slab|head|node=3D0|zone=3D2|lastcpupi=
d=3D0xffff|kasantag=3D0x0)
> [    0.000000] Object 0xf1ff00080001a980 @offset=3D17437937757178562944 f=
p=3D0x0000000000000000
> [    0.000000]
> [    0.000000] Redzone  ffff00080001a900: cc cc cc cc cc cc cc cc cc cc c=
c cc cc cc cc cc  ................
> [    0.000000] Redzone  ffff00080001a910: cc cc cc cc cc cc cc cc cc cc c=
c cc cc cc cc cc  ................
> [    0.000000] Redzone  ffff00080001a920: cc cc cc cc cc cc cc cc cc cc c=
c cc cc cc cc cc  ................
> [    0.000000] Redzone  ffff00080001a930: cc cc cc cc cc cc cc cc cc cc c=
c cc cc cc cc cc  ................
> [    0.000000] Redzone  ffff00080001a940: cc cc cc cc cc cc cc cc cc cc c=
c cc cc cc cc cc  ................
> [    0.000000] Redzone  ffff00080001a950: cc cc cc cc cc cc cc cc cc cc c=
c cc cc cc cc cc  ................
> [    0.000000] Redzone  ffff00080001a960: cc cc cc cc cc cc cc cc cc cc c=
c cc cc cc cc cc  ................
> [    0.000000] Redzone  ffff00080001a970: cc cc cc cc cc cc cc cc cc cc c=
c cc cc cc cc cc  ................
> [    0.000000] Object   ffff00080001a980: 00 00 00 00 00 00 00 00 ff 00 0=
0 00 00 00 00 00  ................
> [    0.000000] Object   ffff00080001a990: 00 00 00 00 00 00 00 00 00 00 0=
0 00 00 00 00 00  ................
> [    0.000000] Object   ffff00080001a9a0: 00 00 00 00 00 00 00 00 00 00 0=
0 00 00 00 00 00  ................
> [    0.000000] Object   ffff00080001a9b0: 00 00 00 00 00 00 00 00 00 00 0=
0 00 00 00 00 00  ................
> [    0.000000] Object   ffff00080001a9c0: 00 00 00 00 00 00 00 00 00 00 0=
0 00 00 00 00 00  ................
> [    0.000000] Object   ffff00080001a9d0: 00 00 00 00 00 00 00 00 00 00 0=
0 00 00 00 00 00  ................
> [    0.000000] Object   ffff00080001a9e0: 00 00 00 00 00 00 00 00 00 00 0=
0 00 00 00 00 00  ................
> [    0.000000] Object   ffff00080001a9f0: 00 00 00 00 00 00 00 00 00 00 0=
0 00 00 00 00 00  ................
> [    0.000000] Redzone  ffff00080001aa00: cc cc cc cc cc cc cc cc        =
                  ........
> [    0.000000] Padding  ffff00080001aa54: 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5=
a 5a 5a 5a 5a 5a  ZZZZZZZZZZZZZZZZ
> [    0.000000] Padding  ffff00080001aa64: 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5=
a 5a 5a 5a 5a 5a  ZZZZZZZZZZZZZZZZ
> [    0.000000] Padding  ffff00080001aa74: 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5=
a 5a              ZZZZZZZZZZZZ
> [    0.000000] CPU: 0 PID: 0 Comm: swapper/0 Not tainted 6.4.0-00001-g56e=
11237836c #1
> [    0.000000] Hardware name: FVP Base RevC (DT)
> [    0.000000] Call trace:
> [    0.000000]  dump_backtrace+0xec/0x108
> [    0.000000]  show_stack+0x18/0x2c
> [    0.000000]  dump_stack_lvl+0x50/0x68
> [    0.000000]  dump_stack+0x18/0x24
> [    0.000000]  print_trailer+0x1ec/0x230
> [    0.000000]  check_bytes_and_report+0x110/0x154
> [    0.000000]  check_object+0x31c/0x360
> [    0.000000]  free_to_partial_list+0x174/0x5d8
> [    0.000000]  __slab_free+0x220/0x28c
> [    0.000000]  __kmem_cache_free+0x364/0x3dc
> [    0.000000]  kfree+0x50/0x70
> [    0.000000]  apply_wqattrs_prepare+0x244/0x2a4
> [    0.000000]  apply_workqueue_attrs+0x5c/0xb4
> [    0.000000]  alloc_workqueue+0x368/0x4f8
> [    0.000000]  workqueue_init_early+0x2e8/0x3ac
> [    0.000000]  start_kernel+0x168/0x394
> [    0.000000]  __primary_switched+0xbc/0xc4
> [    0.000000] Disabling lock debugging due to kernel taint
> [    0.000000] FIX kmalloc-128: Restoring kmalloc Redzone 0xffff00080001a=
9b0-0xf1ff00080001a9ff=3D0xcc
> [    0.000000] FIX kmalloc-128: Object at 0xf1ff00080001a980 not freed
>
>
>
> --
> You received this message because you are subscribed to the Google Groups=
 "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgi=
d/kasan-dev/20230628154714.GB22090%40willie-the-truck.



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
kasan-dev/CAG_fn%3DUW0pX5%2BkRqqr9LH5wYbvA%3D1rABW8K%2BtrGd-Jt8aynTww%40mai=
l.gmail.com.
