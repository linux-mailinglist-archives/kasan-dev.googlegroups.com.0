Return-Path: <kasan-dev+bncBCMIZB7QWENRBTO5VD6QKGQERRQ5G7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E7ED2ACF6A
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 07:10:22 +0100 (CET)
Received: by mail-io1-xd37.google.com with SMTP id p67sf7520638iod.9
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Nov 2020 22:10:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604988621; cv=pass;
        d=google.com; s=arc-20160816;
        b=zQMY0RdkYBV/PQzBmC6G4eO3Ofuw9cHarttAeOGuAuYkwtls+DNcRXniIBkoQUCVqp
         66CIlCKjEMzTU5ngV+tJQpgTMpb2reSLd+OGDzfItzQzcv3aOUoeuwbGDZm8jfVXWXu6
         KsrNnmLFvXeDz5HbAOUGIn28R5TrmuI6DqsAQFadQ8/beDpYbCDvKW6IIy9RVJK0+xCm
         uFfojLkvFI7VYlXpcSUaALRPTH+jJuaNn2Ah4unndAJ0L9h3R0Czo+B2F2RDXBITPZS5
         UWAiDMfAahFLOTBHHVu+LZuJwVfEgLduL0ZokFQ50T1mu99driBm8lgxMQDNQJ+mcmDn
         o2fQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=qKCNjCZU//RsOWe0n8NFQqdkS9DCsr6IhgJ3fsLRRbo=;
        b=v2n7jQBlsbV2fPL759whLIPJzJgWD5Fm27nrD5gsv5/4kGN+BuOvHkq/h+mzeK0kbh
         iZa4G4P19ZL1+82Kf/F5oM6oxe5rpZ+u5Y+ajmrgprikz4AP26vD2ZbRoiaG9azJVB8r
         vEQLDsxAKHgivaac6loYcDXtldQ20IH7cfWwklru8Eklne435mQLhzdE8R3+c1xen9xk
         /35uW3jlkNcWHzt2+Cs+/8w5TSyB9lPZ5kasHTa8hNpOMCi8pBnZ1YNKUAHAP527BGQ8
         fLJp2CnqLfvzOwo684biB8PUWMAx5VYc/9MbDcJQZ130I0VanVDQKffnBhrdyXfC82wf
         Fh8Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="R5MSczq/";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qKCNjCZU//RsOWe0n8NFQqdkS9DCsr6IhgJ3fsLRRbo=;
        b=oqHtQM2A8Lkv2Nh3u4lYhE/9LMcH8CkUcPY24O18s7oPqr6hDsmFbwF16VAzPpctl/
         FuoQTmXSYXNGYO3S//Xriab2Co07WI0bjCHAX7lf+FixReYs2vzY+qy0fzURZ7QmJXaG
         4xaBNjpARwcQ/X8IV9CPjEVaA9xNUJ4e1SNVfohmrnr/DQaZiXJbhQZ7HpfYAQFkYqOa
         A+34/VPuIMA699Yqi5uuzd78iZNK2ffQogNgwilHeolAsmR3lnOX9WUIFrAU46iYd9i8
         nIMmXf2gvcO88xImFt7sgK4O8WBLdqW4ZtdfHJ8zD8aXmVKVvHVUGgV3kkZA0vjHgQSK
         iDqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qKCNjCZU//RsOWe0n8NFQqdkS9DCsr6IhgJ3fsLRRbo=;
        b=fsPf8FMzumiIlAjp7OeZ+J/89Hh2GeMqGUeSSZXiHfn/Vq4Gu+on3ImnzqSb78x4UA
         XWZCrCS6ASR9+C9GUcNa4GDJTXdjv5DpaLYkNYKWyCok/P7iRo/7tn7dN7EVFMLMH5Qs
         tWs9u+Xf7Ca0ZMxiep86Tt5c0v6gzmC+zBxvCcO/8txhnr/55dUV5LAMaXfJ7OaKTIDh
         Hh4eTQ5ghOhfXlVpq1HuonG/U6oPLW4PNYkqoF1UvEizGcKXjTva9MlB7InPdnfXiekU
         oN+QxJJpAJnQshTq6kRqIG8BLrey2XknENH1dx0hKelwltYg8kAVWJu9XsWuH9X8pnUE
         EvcA==
X-Gm-Message-State: AOAM5321P5780keH0h6n+nYZEv3eqG8S34PGSgefq0EaH5rCzPbHtG2a
	oa6pYObEDFmkpsruYs709PA=
X-Google-Smtp-Source: ABdhPJzIYyBsmnD6B+COQssC7aFpqGe+wmxGYzz/ucVVrd7HR6wMzPoRR/DoonStvcA2ecwDDPdL/Q==
X-Received: by 2002:a92:cb51:: with SMTP id f17mr12440524ilq.64.1604988621167;
        Mon, 09 Nov 2020 22:10:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:c557:: with SMTP id g23ls1225274jaj.9.gmail; Mon, 09 Nov
 2020 22:10:20 -0800 (PST)
X-Received: by 2002:a05:6638:22a6:: with SMTP id z6mr13445109jas.62.1604988620723;
        Mon, 09 Nov 2020 22:10:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604988620; cv=none;
        d=google.com; s=arc-20160816;
        b=zlNpaoxEeN+wnzIlgMz/BFY9Fsg7ExDrOuNxoRSVSoljWZsglW3ze37Ay/EtQ6zaLY
         2lRXkz3Cp71tOAs3hixuLsHtBoqdIrMoulqbZz67EoQLaI72RNIuY5WHlosyNQqh+s4b
         wRSZ5hVy0iJdmxTPAl3j5Vk8n2DA6J+3PDDRZeIIvEGiWdrAZlkZ6QRRqeOwdvKIpwlS
         tbGZYP3KAjBrqx4ZNdRus9cPYdn5PoKdWE2JH7Bje+lGLt/DRZjWUiSlnV31NR1GVyCJ
         Qw9Xhm+VmDs0k29MdhFyOmIGu+hkICQa4bRo92FkiToS+OT2NE/cNW8BtmAcWwcsmusP
         J4iw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Sry2lTr7MR7oPl6fa6+3WmlS6qceNTjPKWT+cj+xu1M=;
        b=gNMUEAGC5yXVdnKSqcZUDigyDsJYX2czki/ViR+fS9mZzphfBNmESqmIY7MbyTVnA5
         vxmaQ94Rj8IZm4S231nGEV2rd1QtJXS0XHGdFpC7OisSCUQ27naKMXWirs19dPLBuz1/
         r7sdgJio4fdzGEb6j6+uaq+d/wQaoAoo2aFby8zPYXOH19vp9WTVDziT9sqLB5Yh+BA6
         Q99exLf+jC1SiuLOVlOFeCvfbbi0SoHnMRDGimKYPgheZbaHF8EAXjsSh2r7leR71Los
         nhv0W96dfQV/1vuOk+/53EglEMYmgeS4uSiaz3DaOwdweJCVp0LFNAOVh8BkGkc80y+b
         Rk/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="R5MSczq/";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id h8si659961iog.4.2020.11.09.22.10.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Nov 2020 22:10:20 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id q5so6281200qkc.12
        for <kasan-dev@googlegroups.com>; Mon, 09 Nov 2020 22:10:20 -0800 (PST)
X-Received: by 2002:a37:49d6:: with SMTP id w205mr17820769qka.501.1604988619896;
 Mon, 09 Nov 2020 22:10:19 -0800 (PST)
MIME-Version: 1.0
References: <a4c8cee1-a7ed-70cb-ade5-958555ab16cd@pengutronix.de>
In-Reply-To: <a4c8cee1-a7ed-70cb-ade5-958555ab16cd@pengutronix.de>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 10 Nov 2020 07:10:00 +0100
Message-ID: <CACT4Y+bf7_CC7KxVS3So3mOKMSbRPe6t_zHYB4iaiihRDoEDaQ@mail.gmail.com>
Subject: Re: Inconclusive KASAN report on ARM32
To: Ahmad Fatoum <a.fatoum@pengutronix.de>
Cc: Linus Walleij <linus.walleij@linaro.org>, Florian Fainelli <f.fainelli@gmail.com>, 
	Abbott Liu <liuwenliang@huawei.com>, Ard Biesheuvel <ardb@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Mike Rapoport <rppt@linux.ibm.com>, 
	Alexander Potapenko <glider@google.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	netdev <netdev@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Pengutronix Kernel Team <kernel@pengutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="R5MSczq/";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Thu, Nov 5, 2020 at 11:26 PM Ahmad Fatoum <a.fatoum@pengutronix.de> wrote:
>
> Hello,
>
> I am looking at an arm32 KernelAddressSanitizer report[1] and trying to make sense of it.
>
> According to the report, KASAN chokes on the second line:
>
>         rt = skb_rtable(skb);
>         if (rt->rt_type == RTN_MULTICAST) { /* rt shouldn't have been dereferenced here */
>
> The log itself doesn't indicate however why KASAN thinks that rt is no longer
> valid. The memory state dump says:
>
>         Memory state around the buggy address:
>          e6cae000: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
>          e6cae080: fc fc fc fc fc fc fc fc 00 00 00 00 00 00 00 00
>         >e6cae100: 00 00 00 00 00 00 00 fc fc fc fc fc fc fc fc fc
>                          ^
> Extra Annotation:     ^  `- 0xe6ca_e110
>                        `--  0xe6ca_e108
>
> This is strange:
>
> 1. The marker points at 0xe6cae100 + 2 * 8 =  [0xe6ca_e110-0xe6ca_e118],
>    which does not cover the address where the error was reported for (0xe6ca_e10c).
>    (Maybe because of the shadow_addr++ line in get_shadow_bug_type?)
>
> 2. The whole 120 bytes region for the struct rtable is marked accessible,
>    so why is KASAN even reporting an error here?
>
>
> I am not sure whether this is an issue with the non-yet-mainline ARM32 KASAN
> patch set, a false positive within KASAN itself and if my problem is really
> in the network stack.
>
> The ARM32 KASAN patch set I use was Linus Walleij's v15 with 1 patch on top:
> https://lore.kernel.org/linux-arm-kernel/20201014105958.21027-1-a.fatoum@pengutronix.de
>
> This was applied on top of v5.9.0. The issue I hoped to look at closely is
> that with high network bandwidth use (60 Mbit/s video streams) and CPU pressure
> (decoding video streams, Load average: 6.50), I run into kernel memory corruption
> after a day or two. With KASAN enabled, I got multiple stack traces around the
> network stack, some of them pointing at memory states of all zero and some don't.

Hi Ahmad,

Such confusing reports may happen due to [intentional] races in KASAN
code. Namely, first there is an access validity check, it observed a
"bad" shadow. Then reporting code re-loaded shadow to print bug type
and shadow around the access. That does not happen atomically with the
initial check, so it's possible that another CPU has re-allocated the
object and changed the shadow to "good".

There are 2 most common reasons for such a race:
1. The code does a use-after-free, but the use happens long after the
free. In such case the object may be evicted from the KASAN quarantine
and re-allocated.
2. The code does a wild access which hits a random address and that
heap object just happened to be re-allocated right around the access
time.

Since you are saying that you got multiple reports and some of them
look more consistent, I would suggest to just start looking at the
more consistent reports and start fixing these bugs. Then it's likely
that the inconsistent reports will go away as well. And then you don't
need to debug them at all.



> [0]:
>
> [24507.728709] ==================================================================
> [24507.736028] BUG: KASAN: out-of-bounds in ip_rcv_finish_core.constprop.0+0x11c0/0x1480
> [24507.743888] Read of size 2 at addr e6cae10c by task udpsrc2:src/360
> [24507.750166]
> [24507.751681] CPU: 0 PID: 360 Comm: udpsrc2:src Tainted: G        W         5.9.0-20201014-1 #1
> [24507.760218] Hardware name: Freescale i.MX6 Quad/DualLite (Device Tree)
> [24507.766756] Backtrace:
> [24507.769241] [<c011e1c4>] (dump_backtrace) from [<c011e878>] (show_stack+0x20/0x24)
> [24507.776836]  r9:d07f2494 r8:e716a000 r7:40030193 r6:c2730e00 r5:00000000 r4:c2730e00
> [24507.784610] [<c011e858>] (show_stack) from [<c0f41bd8>] (dump_stack+0x8c/0xa4)
> [24507.791865] [<c0f41b4c>] (dump_stack) from [<c06d4794>] (print_address_description.constprop.0+0x3c/0x4b0)
> [24507.801535]  r7:00000000 r6:c1ab4bf8 r5:efbec878 r4:e6cae10c
> [24507.807219] [<c06d4758>] (print_address_description.constprop.0) from [<c06d4e24>] (kasan_report+0x160/0x17c)
> [24507.817151]  r8:e716a000 r7:00000000 r6:c1ab4bf8 r5:00000168 r4:e6cae10c
> [24507.823878] [<c06d4cc4>] (kasan_report) from [<c06d5c98>] (__asan_report_load2_noabort+0x1c/0x20)
> [24507.832767]  r7:8c155088 r6:c286a100 r5:e6cae0c0 r4:d07f2400
> [24507.838456] [<c06d5c7c>] (__asan_report_load2_noabort) from [<c1ab4bf8>] (ip_rcv_finish_core.constprop.0+0x11c0/0x1480)
> [24507.849263] [<c1ab3a38>] (ip_rcv_finish_core.constprop.0) from [<c1ab4f18>] (ip_rcv_finish+0x60/0x100)
> [24507.858590]  r10:c1ab74a4 r9:e716a054 r8:c284b180 r7:d07f2400 r6:e716a000 r5:c284b180
> [24507.866430]  r4:d07f2400
> [24507.868988] [<c1ab4eb8>] (ip_rcv_finish) from [<c1ab764c>] (ip_rcv+0x1a8/0x1c8)
> [24507.876310]  r5:e6eab160 r4:bbdd561c
> [24507.879917] [<c1ab74a4>] (ip_rcv) from [<c1942ebc>] (__netif_receive_skb_core+0x1684/0x2930)
> [24507.888373]  r8:00000008 r7:e6eab280 r6:d001b3c0 r5:e716a000 r4:d10bea00
> [24507.895101] [<c1941838>] (__netif_receive_skb_core) from [<c19458fc>] (__netif_receive_skb_list_core+0x3f0/0xa2c)
> [24507.905383]  r10:00000000 r9:e6eab380 r8:e716a6a4 r7:e716a6a4 r6:e716a6a4 r5:b9217d40
> [24507.913223]  r4:d10bea00
> [24507.915783] [<c194550c>] (__netif_receive_skb_list_core) from [<c194668c>] (netif_receive_skb_list_internal+0x754/0xe50)
> [24507.926673]  r10:e6eab440 r9:c2d5d020 r8:e716a6a4 r7:e716a6a4 r6:e6eab4a0 r5:00000000
> [24507.934512]  r4:e716a6a4
> [24507.937072] [<c1945f38>] (netif_receive_skb_list_internal) from [<c19475fc>] (gro_normal_list.part.0+0x24/0xec)
> [24507.947179]  r10:00000001 r9:e716a630 r8:00000000 r7:00000000 r6:e716a628 r5:e716a6a4
> [24507.955018]  r4:e716a620
> [24507.957578] [<c19475d8>] (gro_normal_list.part.0) from [<c194b8b4>] (napi_complete_done+0x208/0x620)
> [24507.966724]  r5:e716a620 r4:00000000
> [24507.970334] [<c194b6ac>] (napi_complete_done) from [<c14cf7c0>] (fec_enet_rx_napi+0x2058/0x275c)
> [24507.979143]  r10:e7178000 r9:e716a000 r8:d204f420 r7:d2049ac2 r6:e716a60c r5:1ce2d4b0
> [24507.986982]  r4:00000000
> [24507.989544] [<c14cd768>] (fec_enet_rx_napi) from [<c194c200>] (net_rx_action+0x534/0x1390)
> [24507.997830]  r10:e716a624 r9:e6eab780 r8:e716a628 r7:1ce2d4c4 r6:00000000 r5:00000001
> [24508.005669]  r4:e716a620
> [24508.008231] [<c194bccc>] (net_rx_action) from [<c010194c>] (__do_softirq+0x314/0xf54)
> [24508.016082]  r10:00000003 r9:e6ea8000 r8:00000004 r7:184c0a11 r6:00000008 r5:00000004
> [24508.023921]  r4:c260508c
> [24508.026482] [<c0101638>] (__do_softirq) from [<c0176034>] (irq_exit+0x1e4/0x238)
> [24508.033900]  r10:c25dfed0 r9:e60ca800 r8:e6eab8b8 r7:00000001 r6:26e2a000 r5:26e2a000
> [24508.041739]  r4:c2606f58
> [24508.044305] [<c0175e50>] (irq_exit) from [<c027bf20>] (__handle_domain_irq+0xf8/0x1fc)
> [24508.052239]  r7:00000001 r6:00000000 r5:00000000 r4:c25dfed0
> [24508.057923] [<c027be28>] (__handle_domain_irq) from [<c01015f4>] (gic_handle_irq+0x5c/0xa0)
> [24508.066295]  r10:c290cae0 r9:e6eab8b8 r8:f4001100 r7:f4000100 r6:f400010c r5:c27331a0
> [24508.074134]  r4:c260769c
> [24508.076690] [<c0101598>] (gic_handle_irq) from [<c0100b0c>] (__irq_svc+0x6c/0xac)
> [24508.084186] Exception stack(0xe6eab8b8 to 0xe6eab900)
> [24508.089252] b8a0:                                                       e9409d00 d0a56000
> [24508.097451] b8c0: 000a8600 000a8700 c25dfd00 d18b4d00 60030013 e6119500 e6119500 d18b4d00
> [24508.097451] b8c0: 000a8600 000a8700 c25dfd00 d18b4d00 60030013 e6119500 e6119500 d18b4d00
> [24508.105649] b8e0: c290cae0 e6eab934 e6eab8c8 e6eab908 c1ec9204 c06d62bc 80030013 ffffffff
> [24508.113847]  r9:e6ea8000 r8:e6119500 r7:e6eab8ec r6:ffffffff r5:80030013 r4:c06d62bc
> [24508.121616] [<c06d6234>] (quarantine_put) from [<c06d3940>] (__kasan_slab_free+0x10c/0x130)
> [24508.129984]  r7:c18d9c30 r6:00000001 r5:00000000 r4:d18b4d00
> [24508.135666] [<c06d3834>] (__kasan_slab_free) from [<c06d3fe8>] (kasan_slab_free+0x14/0x18)
> [24508.143951]  r9:40000000 r8:c2912740 r7:c18d9c30 r6:ef8ef950 r5:d18b4d00 r4:e6119500
> [24508.151716] [<c06d3fd4>] (kasan_slab_free) from [<c06d1718>] (kmem_cache_free+0x9c/0x558)
> [24508.159924] [<c06d167c>] (kmem_cache_free) from [<c18d9c30>] (kfree_skbmem+0xb0/0x15c)
> [24508.167863]  r10:c290cae0 r9:40000000 r8:0000001e r7:0000001e r6:d0f7ee0c r5:c28a4414
> [24508.175702]  r4:d18b4d00
> [24508.178263] [<c18d9b80>] (kfree_skbmem) from [<c18f27f0>] (__consume_stateless_skb+0x70/0x3ac)
> [24508.186908] [<c18f2780>] (__consume_stateless_skb) from [<c1ba7a34>] (skb_consume_udp+0xf8/0x228)
> [24508.195800]  r9:40000000 r8:0000001e r7:0000001e r6:d0f7ee0c r5:d0f7ed00 r4:d18b4d00
> [24508.203569] [<c1ba793c>] (skb_consume_udp) from [<c1ba8318>] (udp_recvmsg+0x7b4/0x17c0)
> [24508.211591]  r8:0000001e r7:0000001e r6:e6eabee0 r5:d0f7ed00 r4:d18b4d00
> [24508.218320] [<c1ba7b64>] (udp_recvmsg) from [<c1bdb368>] (inet_recvmsg+0x194/0x508)
> [24508.225998]  r10:c1bdb1d4 r9:e6eabee4 r8:d0f7ed00 r7:e6eabee0 r6:c1ba7b64 r5:e6eabbe0
> [24508.233838]  r4:bbdd5770
> [24508.236405] [<c1bdb1d4>] (inet_recvmsg) from [<c18b45bc>] (____sys_recvmsg+0x2c8/0x5b0)
> [24508.244430]  r10:c1bdb1d4 r9:e6eabee4 r8:1cdd57dc r7:e6eabf00 r6:bbdd578c r5:e4a8a280
> [24508.252269]  r4:e6eabee0
> [24508.254828] [<c18b42f4>] (____sys_recvmsg) from [<c18b9630>] (___sys_recvmsg+0xdc/0x120)
> [24508.262939]  r10:00000000 r9:a66029b4 r8:40000000 r7:e4a8a280 r6:e6eabee0 r5:e6eabe40
> [24508.270779]  r4:bbdd57b0
> [24508.273333] [<c18b9554>] (___sys_recvmsg) from [<c18ba434>] (__sys_recvmsg+0xc0/0x154)
> [24508.281270]  r10:00000129 r9:e6ea8000 r8:e4a8a280 r7:40000000 r6:a66029b4 r5:e6eabf60
> [24508.289110]  r4:bbdd57d4
> [24508.291664] [<c18ba374>] (__sys_recvmsg) from [<c18ba4e4>] (sys_recvmsg+0x1c/0x20)
> [24508.299253]  r8:c0100268 r7:00000129 r6:a6603890 r5:00000043 r4:40000000
> [24508.305974] [<c18ba4c8>] (sys_recvmsg) from [<c0100060>] (ret_fast_syscall+0x0/0x58)
> [24508.313728] Exception stack(0xe6eabfa8 to 0xe6eabff0)
> [24508.318799] bfa0:                   40000000 00000043 00000043 a66029b4 40000000 00000000
> [24508.326998] bfc0: 40000000 00000043 a6603890 00000129 00000005 a66029b4 a6602a88 a66029f4
> [24508.335190] bfe0: 00000000 a66028d8 a6603890 465240a0
> [24508.340248]
> [24508.341753] Allocated by task 313:
> [24508.345175]  kasan_save_stack+0x24/0x48
> [24508.349028]  __kasan_kmalloc.constprop.0+0xb8/0xc4
> [24508.353835]  kasan_slab_alloc+0x18/0x1c
> [24508.357687]  kmem_cache_alloc+0x254/0x648
> [24508.361711]  dst_alloc+0x11c/0x1a4
> [24508.365132]  rt_dst_alloc+0x5c/0x468
> [24508.368724]  ip_route_input_rcu+0x1434/0x291c
> [24508.373099]  ip_route_input_noref+0xbc/0xfc
> [24508.377302]  ip_rcv_finish_core.constprop.0+0x218/0x1480
> [24508.382629]  ip_rcv_finish+0x60/0x100
> [24508.386308]  ip_rcv+0x1a8/0x1c8
> [24508.389470]  __netif_receive_skb_core+0x1684/0x2930
> [24508.394366]  __netif_receive_skb_list_core+0x3f0/0xa2c
> [24508.399521]  netif_receive_skb_list_internal+0x754/0xe50
> [24508.404848]  gro_normal_list.part.0+0x24/0xec
> [24508.409221]  napi_complete_done+0x208/0x620
> [24508.413422]  fec_enet_rx_napi+0x2058/0x275c
> [24508.417621]  net_rx_action+0x534/0x1390
> [24508.421473]  __do_softirq+0x314/0xf54
> [24508.425142]
> [24508.426647] The buggy address belongs to the object at e6cae0c0
> [24508.426647]  which belongs to the cache ip_dst_cache of size 120
> [24508.438574] The buggy address is located 76 bytes inside of
> [24508.438574]  120-byte region [e6cae0c0, e6cae138)
> [24508.448843] The buggy address belongs to the page:
> [24508.453656] page:5b8ef13d refcount:1 mapcount:0 mapping:00000000 index:0x0 pfn:0x36cae
> [24508.461586] flags: 0x200(slab)
> [24508.464668] raw: 00000200 00000100 00000122 e69c9600 00000000 80150015 ffffffff 00000001
> [24508.472771] raw: 00000000
> [24508.475401] page dumped because: kasan: bad access detected
> [24508.480980]
> [24508.482480] Memory state around the buggy address:
> [24508.487284]  e6cae000: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
> [24508.493826]  e6cae080: fc fc fc fc fc fc fc fc 00 00 00 00 00 00 00 00
> [24508.500368] >e6cae100: 00 00 00 00 00 00 00 fc fc fc fc fc fc fc fc fc
> [24508.506904]                  ^
> [24508.509974]  e6cae180: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
> [24508.516514]  e6cae200: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
> [24508.523049] ==================================================================
> [24508.530278] Disabling lock debugging due to kernel taint
>
> --
> Pengutronix e.K.                           |                             |
> Steuerwalder Str. 21                       | http://www.pengutronix.de/  |
> 31137 Hildesheim, Germany                  | Phone: +49-5121-206917-0    |
> Amtsgericht Hildesheim, HRA 2686           | Fax:   +49-5121-206917-5555 |
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a4c8cee1-a7ed-70cb-ade5-958555ab16cd%40pengutronix.de.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bbf7_CC7KxVS3So3mOKMSbRPe6t_zHYB4iaiihRDoEDaQ%40mail.gmail.com.
