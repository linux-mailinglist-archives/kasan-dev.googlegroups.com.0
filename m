Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBSXF6WVAMGQEOJ37BBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0F9F07F3C41
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Nov 2023 04:17:32 +0100 (CET)
Received: by mail-ot1-x33f.google.com with SMTP id 46e09a7af769-6ce53378ff9sf420725a34.0
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 19:17:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700623050; cv=pass;
        d=google.com; s=arc-20160816;
        b=fOn0+fY8AzfyzU7mUikv66WDE51sPRxpz+TlFS8L8CnMlu9VMr/IYIGmKVPGOZu09G
         5ocKoUR+QMUlZ5506n6qdIQfI1Zb2m7p7cm125JCqPHeAcqhZEpEgYdCBydId2ZO3PAf
         Oogb6qUBwCa97W8zD3Uj5qEexuXsQ/zgKzYVYAtBpaj3b99T6Yf4/h0+X8ItpBbczSqx
         mMvEF26cjdSTpsIKzuvEcT0oS23L+jI57s6VceQ/ZcvgHa8NyGq9tYXD9u7FanIxgXx7
         yLox8XC6tt7U59sXKGtZpzASLQWr3qIWr3rjx4wNOd16bwm3U9BWkrENe0M7NNbFED+5
         zKAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=CMjxicsaZsCnnZH5BKps6nu90utEbpV5c9PeWEzx+Ns=;
        fh=f4NfliIws/m/cVxsN15bE/hKmzbPReAFB+nEzn1MMbs=;
        b=WBnzAl67Z/azIO0xAye5WA+19De/EKaNDEOqUFKhzjFw2ctwT0nee+9fN/ACBskxzv
         0tp9x3QRSRjl8gI7Jpe4SsjGLKK4l/8kGZoqbXxMVpY5OwVObYquiD3PYO9zlPCMDLFw
         kgIMf/zoxOyC2KlvHeiS5zvDRZmx7c1Y33x6TP49PJjIAvbAEmzausV2o5qlq0RG34cU
         //H3LsGCrChOxJuduZpYCiK3X7HFu3niy9SKdBA7JDIpRqCaet0U/kqjwvH4f0UY18bg
         KjADVMaAcVqhgFqQBpe8Sk3MqQ1rLf1amarHsxrrv5m8AVz3fCOrwCLJTrCj3B4lFkuw
         nONQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="FtlrFt/B";
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::e2a as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700623050; x=1701227850; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=CMjxicsaZsCnnZH5BKps6nu90utEbpV5c9PeWEzx+Ns=;
        b=hZvbIycCzw04DYHyP4eFxHPRHiHQpTCyZ6Jh1WIApdAYu+Q9OdV+1zwWDHstlUpzMu
         JEElsw3o8LToDDUWVrV8D9PEFxUCuuiK6pyksOyzyduVM/80LgZV6EUQqvnKzIycLPG9
         r603tDw1Qpm8jyHQBPIWX32gQxR7cqoQDbABS5SbZb4U6s+51l0E4oMoBIzShLyHU0Gl
         iZdmsXLfOQiggnScblv8pE4vxG0olVJeyuvK8+3iIgNj+WJ00UtJXllepAfLujYjUp0L
         U0VuKXLjl+ynQ3TDcJmYYiCYabheehLEcFEbG3mdWGGWhmsgz2b6Bkffbva/ZtUHjosc
         Wbbg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1700623050; x=1701227850; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=CMjxicsaZsCnnZH5BKps6nu90utEbpV5c9PeWEzx+Ns=;
        b=Gh44djBd5GkESY0PK2R2V8CJBv2gJ+bDCqrVQAO5fRUuiXw9Fc1manT6FTr/yZo4Dk
         crfE07SkVnW3OqoNBfb8PrVJZbU7lV0iySWmvjskd3zA26V6A+cChT6YgqNVn+oM20M8
         8fqBiNdws0LoFMiC/p23STStMKLX20ckrfMZRHuzR4cHjFQfwpdx9jjqy4puGhI3z2Qf
         0vXnKn2jaNaKR9BkV7SN6nEGdyNKX8viZy6SIe2SjKQ/0JhrGEYS9aKl/+MSR1QVIsJf
         CnPWjUmEr93fXTLXqISNTKWmu2tqw2W+BT8NpbGtiRwD7fuH1sjgoYSn3vcaNb0VCL9/
         9bzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700623050; x=1701227850;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=CMjxicsaZsCnnZH5BKps6nu90utEbpV5c9PeWEzx+Ns=;
        b=b3G6oRW4qiSo4HZi82hXP/kvcH9YrQdkx2O2tXJgFc5ETMlGX7eslvfsVZHZmzW3DY
         zr8IbAu9D7pwVWMacqRSaHFEB6UyFIQoVjLKlOGKrwGoBTjC54KDJh3HOe7s8OIvMtJy
         a/+LdFn9UwMDqz78CBd4UMJE5SD/xMceET3eY9j9SfYqxadqS9kdgAcM26F0OwSuLrMd
         etGrdwaCZ3acgjyWG1NFSkTSso1XSIQuD38X/3koRtUbS+eugtAY98rOUGF9WbHcs44i
         VXvB5EE9591pc9OQ+h9ob4isj1JAf85ueByQE0BPzxSErtKQHf82QUl+shcR6lxfDiaD
         gtaA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwkSwuOUKcKNa3fYhpFN6r/0yNZ048wx64qCbGMlVAQ81six5N0
	C8qVNq249c4fIaQZUwkjids=
X-Google-Smtp-Source: AGHT+IGcISEALRp7GcE2DawLUAz8Dn4Dr22cPWnaVp3sr1vtZZRtHFJDsXnLd7BY7XgHtueKt8lofA==
X-Received: by 2002:a9d:7581:0:b0:6bd:62c1:65c with SMTP id s1-20020a9d7581000000b006bd62c1065cmr2362151otk.18.1700623050475;
        Tue, 21 Nov 2023 19:17:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:8c2a:0:b0:587:a54a:b88f with SMTP id u39-20020a4a8c2a000000b00587a54ab88fls1339624ooj.1.-pod-prod-00-us;
 Tue, 21 Nov 2023 19:17:29 -0800 (PST)
X-Received: by 2002:a05:6808:14d6:b0:3b8:37f9:443b with SMTP id f22-20020a05680814d600b003b837f9443bmr1449611oiw.9.1700623049435;
        Tue, 21 Nov 2023 19:17:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700623049; cv=none;
        d=google.com; s=arc-20160816;
        b=l12a3BAeXudXdl+sIRPrZXI9hNKgOlH4iYsgmGuQbYsO6crQhcV9I6t+eil0pPKdGj
         f/cCZuZWxtJOXIUx1vV5M72rB1aTaKxOn0UBryJcC0Jl4HX+NmxbcgOitlBhb6OQf3bP
         uxlIJArj0SE+JOpPPZY1Rk898buSQ7hok+EdhgRlJjhPGXg3QkbT7kExvgNuClEeZWUK
         SLhBvKUyRTs7Zy0h6acGwXZlBTT8579/3gQJq5d0QQmZjCiAkM0PBSdnmu31zlFEJ+IV
         HfAe1Gi1bnI9HhOfEvh1AjKCSmQS9bIXw6i90pAmlLkdJq09DokBjykycEfGPtQgnu46
         hY9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=+cifHwiL86k/hSfKeSdI4QL5cIbDxkzf2iHBxnZU0xs=;
        fh=f4NfliIws/m/cVxsN15bE/hKmzbPReAFB+nEzn1MMbs=;
        b=iai0GEiRru2UXldo1GSnyLoOp5c3cJO47tYh0p0twmywIHW8Dg0aqMDx2UiYYqd+cg
         DK1F5YfHd7lhMIs3r/HKD0uls5f4ymhzHlMJS7PRPH8XsoBtHfqdf4t5wPLISZdgM9TT
         /IvXOKTr7HXm/WagJhTaPB3g8aQz5eKL3o4MCOdHN8f1qUt0WBmkYaTCEW2aqrAKYJfa
         Qpys6IGIxS7nh5RVjKx3n2bif7CnnUCLsXHZz0bBd5GGQMlHBP1U6aOP7yjtVU/TAr6M
         ClZkAYpNvxts3x4IAK3UCzUTOl8zKR77QcnAks2grC5KUo7PnHmetzy98z/Wc2Db5Wuu
         DH7Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="FtlrFt/B";
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::e2a as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-vs1-xe2a.google.com (mail-vs1-xe2a.google.com. [2607:f8b0:4864:20::e2a])
        by gmr-mx.google.com with ESMTPS id m2-20020a0568080f0200b003ae413f2b6esi741881oiw.5.2023.11.21.19.17.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Nov 2023 19:17:29 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::e2a as permitted sender) client-ip=2607:f8b0:4864:20::e2a;
Received: by mail-vs1-xe2a.google.com with SMTP id ada2fe7eead31-45f3b583ce9so266259137.0
        for <kasan-dev@googlegroups.com>; Tue, 21 Nov 2023 19:17:29 -0800 (PST)
X-Received: by 2002:a05:6102:47:b0:462:7c78:ba53 with SMTP id
 k7-20020a056102004700b004627c78ba53mr1343955vsp.16.1700623048669; Tue, 21 Nov
 2023 19:17:28 -0800 (PST)
MIME-Version: 1.0
References: <cover.1700502145.git.andreyknvl@google.com> <5cef104d9b842899489b4054fe8d1339a71acee0.1700502145.git.andreyknvl@google.com>
In-Reply-To: <5cef104d9b842899489b4054fe8d1339a71acee0.1700502145.git.andreyknvl@google.com>
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Date: Wed, 22 Nov 2023 12:17:17 +0900
Message-ID: <CAB=+i9Q95W+w=-KC5vexJuqVi60JJ1P8e-_chegiXOUjB7C3DA@mail.gmail.com>
Subject: [BISECTED] Boot hangs when SLUB_DEBUG_ON=y
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev <kasan-dev@googlegroups.com>, 
	Evgenii Stepanov <eugenis@google.com>, Oscar Salvador <osalvador@suse.de>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="FtlrFt/B";       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::e2a
 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;       dmarc=pass
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

On Tue, Nov 21, 2023 at 1:08=E2=80=AFPM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Evict alloc/free stack traces from the stack depot for Generic KASAN
> once they are evicted from the quaratine.
>
> For auxiliary stack traces, evict the oldest stack trace once a new one
> is saved (KASAN only keeps references to the last two).
>
> Also evict all saved stack traces on krealloc.
>
> To avoid double-evicting and mis-evicting stack traces (in case KASAN's
> metadata was corrupted), reset KASAN's per-object metadata that stores
> stack depot handles when the object is initialized and when it's evicted
> from the quarantine.
>
> Note that stack_depot_put is no-op if the handle is 0.
>
> Reviewed-by: Marco Elver <elver@google.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

I observed boot hangs on a few SLUB configurations.

Having other users of stackdepot might be the cause. After passing
'slub_debug=3D-' which disables SLUB debugging, it boots fine.

compiler version: gcc-11
config: https://download.kerneltesting.org/builds/2023-11-21-f121f2/.config
bisect log: https://download.kerneltesting.org/builds/2023-11-21-f121f2/bis=
ect.log.txt

[dmesg]
(gdb) lx-dmesg
[    0.000000] Linux version 6.7.0-rc1-00136-g0e8b630f3053
(hyeyoo@localhost.localdomain) (gcc (GCC) 11.3.1 20221121 (R3[
0.000000] Command line: console=3DttyS0 root=3D/dev/sda1 nokaslr
[    0.000000] CPU: 0 PID: 0 Comm: swapper Not tainted
6.7.0-rc1-00136-g0e8b630f3053 #22
[    0.000000] RIP: 0010:setup_arch+0x500/0x2250
[    0.000000] Code: c6 09 08 00 48 89 c5 48 85 c0 0f 84 58 13 00 00
48 c1 e8 03 48 83 05 be 97 66 00 01 80 3c 18 00 0f3[    0.000000] RSP:
0000:ffffffff86007e00 EFLAGS: 00010046 ORIG_RAX: 0000000000000009
[    0.000000] RAX: 1fffffffffe40088 RBX: dffffc0000000000 RCX: 1ffffffff11=
ed630
[    0.000000] RDX: 0000000000000000 RSI: feec4698e8103000 RDI: ffffffff88f=
6b180
[    0.000000] RBP: ffffffffff200444 R08: 8000000000000163 R09: 1ffffffff11=
ed628
[    0.000000] R10: ffffffff88f7a150 R11: 0000000000000000 R12: 00000000000=
00010
[    0.000000] R13: ffffffffff200450 R14: feec4698e8102444 R15: feec4698e81=
02444
[    0.000000] FS:  0000000000000000(0000) GS:ffffffff88d5b000(0000)
knlGS:0000000000000000
[    0.000000] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[    0.000000] CR2: ffffffffff200444 CR3: 0000000008f0e000 CR4: 00000000000=
000b0
[    0.000000] Call Trace:
[    0.000000]  <TASK>
[    0.000000]  ? show_regs+0x87/0xa0
[    0.000000]  ? early_fixup_exception+0x130/0x310
[    0.000000]  ? do_early_exception+0x23/0x90
[    0.000000]  ? early_idt_handler_common+0x2f/0x40
[    0.000000]  ? setup_arch+0x500/0x2250
[    0.000000]  ? __pfx_setup_arch+0x10/0x10
[    0.000000]  ? vprintk_default+0x20/0x30
[    0.000000]  ? vprintk+0x4c/0x80
[    0.000000]  ? _printk+0xba/0xf0
[    0.000000]  ? __pfx__printk+0x10/0x10
[    0.000000]  ? init_cgroup_root+0x10f/0x2f0
--Type <RET> for more, q to quit, c to continue without paging--
[    0.000000]  ? cgroup_init_early+0x1e4/0x440
[    0.000000]  ? start_kernel+0xae/0x790
[    0.000000]  ? x86_64_start_reservations+0x28/0x50
[    0.000000]  ? x86_64_start_kernel+0x10e/0x130
[    0.000000]  ? secondary_startup_64_no_verify+0x178/0x17b
[    0.000000]  </TASK>

--
Hyeonggon

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAB%3D%2Bi9Q95W%2Bw%3D-KC5vexJuqVi60JJ1P8e-_chegiXOUjB7C3DA%40mai=
l.gmail.com.
