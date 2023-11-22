Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBL7M66VAMGQERU5XSNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F31F7F4661
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Nov 2023 13:38:09 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-35af1a42812sf46705445ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Nov 2023 04:38:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700656688; cv=pass;
        d=google.com; s=arc-20160816;
        b=deXLFIU/dhAiuAcRjcR0S3+HoVTOcFw0T6FdcZiv+dN/uMw/WEfo1ZgOQfPwPupfhz
         XQXKhO6QY2GF39JiTak4Ecoy+NcP+Cfq4Vp/NUupXCvrmi/1a1jKABhqw+68EgK+Hwqs
         Iz1nm6kfrIxegbmNSQNYBNz0/4uDiD7/YJAUlMcJ6mr2Ov1vShJn9eXayZPO2RNewgvi
         hK+IPF4FtGSx8QdkTo7HccDadtCxWnXsJdUR7udXQ2K6byzpYdkx2SYO2ceE2bBUuIyV
         7v9/qpVB463ZrakCKdDZcKGoz2ybdxTcypMbyi1DG6VVk3HNX7CWf7veNAwM91MoFLC6
         sm8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=e7T9wzxECej1988R5y97ATo7ykImatRuqVorKOlD9pU=;
        fh=AzPFh6Rre3Ch5CqfGYMsrICBkpkRPKUkO/eDUAZOClc=;
        b=tkYiclVtBBK2yNm3UZCU3WvgU21PHsG7MW8uOrh+dBzs6AvYd3ThiY5L6AoqlOqOb3
         jq5mpWRL2L3qZ8LPSM5suq1oHE4EuZjCXQU7kRoNh2GqUZTwstWPj69d/Wub4a595pL+
         IrQOUUPYLDur79gZToXuvuf1fJI2BJO9zd46heXE+U5TExok4HUxdTjERSCGVJzg1Sxl
         JcRwKfa6nrBvVHgigChSsMMzA+mfjm61dquRRstKRC7kHGH8CslgKDNpl0dV6sdsSjk8
         /hU43+eCueTp0sws7/j9exRVlalhsPsQLnc89O9suKCgRsAz3hHLxNFMnabdK3C0SmIp
         YCXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Jsedpl5e;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::931 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700656688; x=1701261488; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=e7T9wzxECej1988R5y97ATo7ykImatRuqVorKOlD9pU=;
        b=Zh8xaKOcmQ0I5CHtRbKqIqVSyWwvidO7yJe1gILyqN/pks0N6J06ycaXo9vmbIQYWh
         90AXSRwp1hI3V7LQdCHU+Bq6JBb4vp32kkWpDDWcrwnpWZq+E6w97uiXSCT78Rtm/xgN
         blcu+tRSDKskhl3nLWJDllSXB2KXNCofY55NL10hEJqt8Mngif9cCLdtrqOtlGvisdoB
         7atcVeUh5fTZzFZtmGKcR6t2YvVCqp7zlz2565Y5bpWzV7iLFmFwX9hQdV5WqQ7KHAxo
         jgGOkhICrTy4n7/KLS0Ae3AHXQvzL9Io3dNRFh5/sj/I7dujCcUUoaJUgZbiwZ+PCqO0
         ECnQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1700656688; x=1701261488; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=e7T9wzxECej1988R5y97ATo7ykImatRuqVorKOlD9pU=;
        b=JmB9h3M9/g+AiTB2+w2T+Np9AFSPiv7X1w5AnE8EWYRIZWHYGBkyhslPAgl0DNFBZt
         OcPLgsU+JAZuVpcuhdJZ010AbqAY32zGzoJ/jSdoQDXeyczhBXR8l4AAuemZmTUc1hRI
         RFfWJB7IW1y9BVG0nSdTcwqxIN6gQncxVjs4ca5QeWfAC1fzXwcAeoq0vheIpBgsGp78
         DC0T8mlPnh3unTzofJEilfHC8UVK3AzJ2Bn2ju0LUT5mafQT1XM+MrwJqfuIN/me9JHF
         3bWubEIY0oiMkC0eGCLso6rfI4iS3OkciMl9HJ81xLzNxazHX/V7NK/ySVqfolaeBU3V
         ftmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700656688; x=1701261488;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=e7T9wzxECej1988R5y97ATo7ykImatRuqVorKOlD9pU=;
        b=l2lMnlpEkZRy0SEn7Dqb50LTyGFIFP0qL0XviRdWHbCHk7rFQ7BABrIWgZA07rT4OU
         pyW90wa+iW/CiH32ycCV1peXYwTqchMCFyZQRSW5ZSoNDNy0Xpdw/5LsoQmoZYKEarTB
         QUNGIZcZ8slZXYG1RpwBv64bx1yo0/uzIyJqOinlOmwahwuXNQ8a4PGADdQl7RvZLaBj
         qc4Ik4EflFHge4nFdfOEzGWrcSCXQJQWzrwPPE0ITfhpWZo3HSTtK0Xlti0UkEtqu5q4
         Lor3Q/gjdaEreX0yDnDBjCXSWTzKcb0PX+7uyqLpGoyhnOq22gERK74lFn28Mf4xEoHM
         GtOQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwvNtgtqpUx8xtix6nZIfCeQYCol3g5fsBXnz2SDd6gRjqpqPz9
	zhekqxKEN+uGqzGEFwkgMco=
X-Google-Smtp-Source: AGHT+IG2lzSAx0pKDqN/u9UhUj4OWCdub1eciPyejMhYaIQEYGdYQ/jD0lobdijLXDXH7V+P7BBlAQ==
X-Received: by 2002:a92:c150:0:b0:357:478f:a744 with SMTP id b16-20020a92c150000000b00357478fa744mr2184725ilh.10.1700656687955;
        Wed, 22 Nov 2023 04:38:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c142:0:b0:35b:375d:9c4a with SMTP id b2-20020a92c142000000b0035b375d9c4als329301ilh.1.-pod-prod-01-us;
 Wed, 22 Nov 2023 04:38:07 -0800 (PST)
X-Received: by 2002:a6b:c584:0:b0:780:c787:637b with SMTP id v126-20020a6bc584000000b00780c787637bmr2349896iof.0.1700656687164;
        Wed, 22 Nov 2023 04:38:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700656687; cv=none;
        d=google.com; s=arc-20160816;
        b=VUmlKjJ6Efxg+211hlxxKA5IcY2ugJe/PfC1Ey+QXXhEnle+L+tlCV6TScEryy8HAZ
         6qJGktDf1dibnXSPfFEp3XZSwAgidWHGGvhiYmBeuD78S+nh6DcyXPLc4/aDWLXpyJhX
         e2F9A+nTjNyePAbdLGmU1cBt8ecEyxAhVRXbswxvR+FX5v2+7Sl4rp/qVDwPW5bEaZCH
         aFMKru3YnyCOtDdd62QwtFTwAzSzBAfngIaC1OR1gFEWz2S+zge+wKj7w5/hnSaAeyTU
         ViuXHpMG03nSwTP9JZHxrHvbi1ceOuSd+nV0Zt0weUcGpajW3lhmtBIlndjHHYx9QTe9
         mnfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=47LDcSAfuEcl+L6+R5MtrU7Ds/aa57XUWW6702q4oOE=;
        fh=AzPFh6Rre3Ch5CqfGYMsrICBkpkRPKUkO/eDUAZOClc=;
        b=qwhkTctKoyW9hy6Kdo3jAItB/CnIE4QaIXlS9zJVE0yjcNE4xNZc0TbuszTpCrE7ck
         TbVIeRqCKMzsvizZZ9welvVNWsw7k8wqJsR8wl4ndQJTpNeggH2DNpuuKfjBBkYaFfxt
         bbjjrwJOODA5DOBKC54pdeNGnyUvXUhBHnHkbJxOPyi7NFVEAfmnHxxONYtI7Z98ws3t
         aK/VEzfPqivMTUATlhZXxueC3LsvnqnSqlEpY1TWO1DptQFHhmZiDCbo7PnadYxfwW4c
         4IkbTSsPQQOfCpt8aOqskxU9dtow0uNvZnWtkEQLPckBvkwjKG286uVY069Z6ZqcYOIp
         KOGA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Jsedpl5e;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::931 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ua1-x931.google.com (mail-ua1-x931.google.com. [2607:f8b0:4864:20::931])
        by gmr-mx.google.com with ESMTPS id c14-20020a02a40e000000b0046682f74a61si52185jal.0.2023.11.22.04.38.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 22 Nov 2023 04:38:07 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::931 as permitted sender) client-ip=2607:f8b0:4864:20::931;
Received: by mail-ua1-x931.google.com with SMTP id a1e0cc1a2514c-7c4452973f5so171794241.0
        for <kasan-dev@googlegroups.com>; Wed, 22 Nov 2023 04:38:07 -0800 (PST)
X-Received: by 2002:a1f:cb86:0:b0:49d:c1f5:d491 with SMTP id
 b128-20020a1fcb86000000b0049dc1f5d491mr2245888vkg.15.1700656686405; Wed, 22
 Nov 2023 04:38:06 -0800 (PST)
MIME-Version: 1.0
References: <cover.1700502145.git.andreyknvl@google.com> <5cef104d9b842899489b4054fe8d1339a71acee0.1700502145.git.andreyknvl@google.com>
 <CAB=+i9Q95W+w=-KC5vexJuqVi60JJ1P8e-_chegiXOUjB7C3DA@mail.gmail.com>
In-Reply-To: <CAB=+i9Q95W+w=-KC5vexJuqVi60JJ1P8e-_chegiXOUjB7C3DA@mail.gmail.com>
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Date: Wed, 22 Nov 2023 21:37:53 +0900
Message-ID: <CAB=+i9Re7BY96_eBjNUct9kdRqkXNXQ1UdYdQxtZ30vEyCT0=g@mail.gmail.com>
Subject: [REGRESSION] Boot hangs when SLUB_DEBUG_ON=y and KASAN_GENERIC=y
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev <kasan-dev@googlegroups.com>, 
	Evgenii Stepanov <eugenis@google.com>, Oscar Salvador <osalvador@suse.de>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, regressions@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Jsedpl5e;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::931
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

On Wed, Nov 22, 2023 at 12:17=E2=80=AFPM Hyeonggon Yoo <42.hyeyoo@gmail.com=
> wrote:
>
> On Tue, Nov 21, 2023 at 1:08=E2=80=AFPM <andrey.konovalov@linux.dev> wrot=
e:
> >
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Evict alloc/free stack traces from the stack depot for Generic KASAN
> > once they are evicted from the quaratine.
> >
> > For auxiliary stack traces, evict the oldest stack trace once a new one
> > is saved (KASAN only keeps references to the last two).
> >
> > Also evict all saved stack traces on krealloc.
> >
> > To avoid double-evicting and mis-evicting stack traces (in case KASAN's
> > metadata was corrupted), reset KASAN's per-object metadata that stores
> > stack depot handles when the object is initialized and when it's evicte=
d
> > from the quarantine.
> >
> > Note that stack_depot_put is no-op if the handle is 0.
> >
> > Reviewed-by: Marco Elver <elver@google.com>
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
> I observed boot hangs on a few SLUB configurations.
>
> Having other users of stackdepot might be the cause. After passing
> 'slub_debug=3D-' which disables SLUB debugging, it boots fine.

Looks like I forgot to Cc regzbot.
If you need more information, please let me know.

#regzbot introduced: f0ff84b7c3a

Thanks,
Hyeonggon

> compiler version: gcc-11
> config: https://download.kerneltesting.org/builds/2023-11-21-f121f2/.conf=
ig
> bisect log: https://download.kerneltesting.org/builds/2023-11-21-f121f2/b=
isect.log.txt
>
> [dmesg]
> (gdb) lx-dmesg
> [    0.000000] Linux version 6.7.0-rc1-00136-g0e8b630f3053
> (hyeyoo@localhost.localdomain) (gcc (GCC) 11.3.1 20221121 (R3[
> 0.000000] Command line: console=3DttyS0 root=3D/dev/sda1 nokaslr
> [    0.000000] CPU: 0 PID: 0 Comm: swapper Not tainted
> 6.7.0-rc1-00136-g0e8b630f3053 #22
> [    0.000000] RIP: 0010:setup_arch+0x500/0x2250
> [    0.000000] Code: c6 09 08 00 48 89 c5 48 85 c0 0f 84 58 13 00 00
> 48 c1 e8 03 48 83 05 be 97 66 00 01 80 3c 18 00 0f3[    0.000000] RSP:
> 0000:ffffffff86007e00 EFLAGS: 00010046 ORIG_RAX: 0000000000000009
> [    0.000000] RAX: 1fffffffffe40088 RBX: dffffc0000000000 RCX: 1ffffffff=
11ed630
> [    0.000000] RDX: 0000000000000000 RSI: feec4698e8103000 RDI: ffffffff8=
8f6b180
> [    0.000000] RBP: ffffffffff200444 R08: 8000000000000163 R09: 1ffffffff=
11ed628
> [    0.000000] R10: ffffffff88f7a150 R11: 0000000000000000 R12: 000000000=
0000010
> [    0.000000] R13: ffffffffff200450 R14: feec4698e8102444 R15: feec4698e=
8102444
> [    0.000000] FS:  0000000000000000(0000) GS:ffffffff88d5b000(0000)
> knlGS:0000000000000000
> [    0.000000] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> [    0.000000] CR2: ffffffffff200444 CR3: 0000000008f0e000 CR4: 000000000=
00000b0
> [    0.000000] Call Trace:
> [    0.000000]  <TASK>
> [    0.000000]  ? show_regs+0x87/0xa0
> [    0.000000]  ? early_fixup_exception+0x130/0x310
> [    0.000000]  ? do_early_exception+0x23/0x90
> [    0.000000]  ? early_idt_handler_common+0x2f/0x40
> [    0.000000]  ? setup_arch+0x500/0x2250
> [    0.000000]  ? __pfx_setup_arch+0x10/0x10
> [    0.000000]  ? vprintk_default+0x20/0x30
> [    0.000000]  ? vprintk+0x4c/0x80
> [    0.000000]  ? _printk+0xba/0xf0
> [    0.000000]  ? __pfx__printk+0x10/0x10
> [    0.000000]  ? init_cgroup_root+0x10f/0x2f0
> --Type <RET> for more, q to quit, c to continue without paging--
> [    0.000000]  ? cgroup_init_early+0x1e4/0x440
> [    0.000000]  ? start_kernel+0xae/0x790
> [    0.000000]  ? x86_64_start_reservations+0x28/0x50
> [    0.000000]  ? x86_64_start_kernel+0x10e/0x130
> [    0.000000]  ? secondary_startup_64_no_verify+0x178/0x17b
> [    0.000000]  </TASK>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAB%3D%2Bi9Re7BY96_eBjNUct9kdRqkXNXQ1UdYdQxtZ30vEyCT0%3Dg%40mail.=
gmail.com.
