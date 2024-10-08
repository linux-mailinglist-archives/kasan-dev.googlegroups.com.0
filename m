Return-Path: <kasan-dev+bncBDAOJ6534YNBBPUUS24AMGQEQ3BSUDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 80FB39957BD
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Oct 2024 21:38:40 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-42cb08ed3a6sf617985e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Oct 2024 12:38:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728416320; cv=pass;
        d=google.com; s=arc-20240605;
        b=Fmkx/N/ExDrYRrIJGnCF4UvzjsppY8GyuNzi0ppceEIgcxbM6/BqvD17H7Q5Gac2Yh
         8cbIchZ5Qt5Cyn4sEUZBYkvCjP7bhcXcGVxY67dKwrcdcU7m+aNlUL+oSRuyOptdU3hI
         ETGX89DNLeooenfxyvP0OR2St0BVqvfu67kCb18rCtrtP/n30dj0Vc62AZ6vjHstB8AX
         HAizsPs3j7BBroAi6873MvLXAKPBgdD0JOpFOOnxOtbbFAA6NW7Y3ftXbw6Y7cz30cI2
         PSS+un9XZMbsDqKGl2zd+Bde3oRnRv1iqNmz2EmeIDoRV2/tu04EboEWOC9S0HkdtfRf
         QMaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=0fPcrrz2tytlxf/zJAgomFbDve5Qi5eLIWXgJLLuqy4=;
        fh=skdZM2m3yD43BAs2CMHKvXpraEgBLARAA/DqbMYyTIY=;
        b=JThRiyJLiM37eVkBLhzEo+hu5zDYpmxy2FO9C8UQxGj22VIiHrWOj5ZwAPLqppaxop
         2NRfZ8+BKJba2/zN8xtGwGOYRSK/tAgD0abhoqNqy8RxxmFlM+ZDbQBXpE5roAaq4Xve
         R+G8CAfw6dj5TlhvATigkvAB4X7RRSRrH6MM8AKbPkOUMg8GXniD2zVzNObrKY+RZxUT
         jTKG++Gl6AJUKgn8HCxviXfuOSAJ4/eP5+uPC0aLhHsVweuhYt4iN378au5v1K04WHRH
         O3nOpnOr/ln2T6sEBxFd8MXMwBQMtldoBdM7LQsqdIkcXc1Wb+D6fDBp9NjhsYjnGUq1
         9XYw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=O6mMpLIt;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::536 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728416320; x=1729021120; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=0fPcrrz2tytlxf/zJAgomFbDve5Qi5eLIWXgJLLuqy4=;
        b=eMKx7mMRVM7WX8krj5lt73GJgwN578vbGMEuW8p8d24tY5XcHyDwScmxDPbByJDGNs
         JioUTOuUFTdQov04kDFh0xdSGRnMJ3n9px5hmGcO7LaELZRFBB7uQ/0WneE5vxRoJ70M
         op6J0bOCCepy/Y1Z9BsJwg9T3HgwsRWj+SdUyg3rGFuNAYZCyv0BliLSc8xVsPvGBdH1
         h0TproLFaZWBchWS5/9iPreuDHfy6Ep6kSSJJ0BI9JJIH7TMKu10RxtZC1BrF9vpaF7K
         6cZIvh6vqq5guSHWqtqA1/1PXBQtilZZs4cLaoyk+hZe+MODVDSu2TF5eJU9YA4PyhFB
         PAmA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728416320; x=1729021120; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0fPcrrz2tytlxf/zJAgomFbDve5Qi5eLIWXgJLLuqy4=;
        b=cNx/rZqWBHuRJO43xb9bZpA62LtDC+6uAltggRBlksJIWCnqQTg68Y90gagztK/82n
         6zI8ohk8eformjl+pAW/GYuFQ9Hu2JBTH4DFsHI1ceJ9Q0h00FtLpj/WvwvU/M7ZBQBp
         /lCLVsugSGN0fV/+co1Zl6Fa6Msbjj9EpRnik+8RzTWxg4x1CjTcLfTmq8iBBiujjPFA
         IzWx6Kcg5MHbbfd5mQtO4B8Lxftw+d9SjAB41+SKch1fodieyrHSBagjnqrP/sCr0TuL
         dRoE/n/Zli15L4OxmUGUHtSz5TO/11m+BWvzuSUpGiSL1JTKO5ToQtZSl8eYCggUgP/B
         E28w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728416320; x=1729021120;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=0fPcrrz2tytlxf/zJAgomFbDve5Qi5eLIWXgJLLuqy4=;
        b=WqvXNThFa1IhUZHNP3aeFKyIGrkdEZaFhm3255YTripA2AIpFcyDYO8i+kG0DqGwXy
         11s8joXpTu129wrogGtxpoDh95+h46d2KYTeBUaKrvFgx9Cr4pcbUsy6YAqcoNopUePC
         LUWC4BU2POvyFPCDpSkMmeg/t3jwCDeeVZrmrV7m6tFIcF9Q8vclFhItcwrNcg2TESwW
         9DTuzeGQNgfUZrcjUDSpbehcv3wQDDCgyHgKVagL03xVGnm8tDW2QAqOGD4qPQfBvW1m
         mqU50+65Yy8gwwwvBa1P5k5HeSKeJioBaMhPza1S43vb9hDBQpenv8LQSxwft6lfL37I
         zSOw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX/CJQJ5EszHwfU+AsZEN6mog7M3zTaYNNyLIqUu2Y2toxs2B9EUnXqGEfwTC5JeAJ/6M+/iQ==@lfdr.de
X-Gm-Message-State: AOJu0YyC+E2jN6WYlrf6tThjuDeXK6QxYzGPv8smXZBRHbOAmdISOBvo
	PY7I3F/nIYU43WKYaFRgJap+rTqELzT3yPZwtEUh/cBAZbYbwMOL
X-Google-Smtp-Source: AGHT+IFbhraNklGCteu4MqTD1Fo+mBlNKTzyNnZa7zPX64Y5JlzS/jQm2lvPXw75hMAwYlhKWXPdkw==
X-Received: by 2002:a05:600c:35c7:b0:42f:6878:a68c with SMTP id 5b1f17b1804b1-430699df165mr1035065e9.13.1728416319100;
        Tue, 08 Oct 2024 12:38:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4617:b0:42b:b737:4a82 with SMTP id
 5b1f17b1804b1-43058b4bf4als509635e9.0.-pod-prod-00-eu-canary; Tue, 08 Oct
 2024 12:38:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU843WXswh+hR1KKRuqAYad/c9b4KrVAXdCqXCfElNMnOp5vrSh/6Vq01FOLXAQcaf5yQY3p1Yn2d8=@googlegroups.com
X-Received: by 2002:a5d:544a:0:b0:37d:34e7:6d22 with SMTP id ffacd0b85a97d-37d3a52259bmr104456f8f.23.1728416317166;
        Tue, 08 Oct 2024 12:38:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728416317; cv=none;
        d=google.com; s=arc-20240605;
        b=BbCzdhMWqLa5jSrm7An6EFwKu98xYDnm945h+dCejdIkSWImC34RwZa/iQtlNcVNsD
         aVxcy9QtASYNVVGnRmU3irGjxViINyTT9g7mayAyy4N5oQlBd76r28Gfg5hAI5TDxn2B
         5V0YricH/1wGkdcrwE7AZXrur2Ax3r55fBPp12s2gDdph0QRvrsJ+rJy90oaigN+oDss
         QCwbQp5HE/esxUofafa+OGmdvmx5r5uN+OpYG5o4dvbU8lZgxoYBSX+K9tDle1WaMaUk
         vhvGcN5zblD+UPZuvYsZ5o7wrugdtbM5SpY4D6UoQLhzaCNZegS7JBgdoJXrjDANAqZM
         olNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=nU/Z0kwK+eaj75ISibAXbIBx/QyJ6gNEXpgdp3T0PQM=;
        fh=/Ecb6GFQv5diYcGsEzYHH4AfIm0yIu1TYldjiVXRzZY=;
        b=N7kcCdKvaleTV6A2VqUzIzit2u/uiZryiAIkp0QrxrrwiCtK22HmML5RAymCIM+W8+
         mNraBSF2pFvmbdEzqGZKVGmyE8T3vZZHQ+SC06h2h16g84lPS8rQTuhXtS4s/iftaaXz
         llD0QXZs2DanfC8NiqqSh71mZ1rVhY00Ts5M4WzN1xLOSahJLrQMpcCs113bI7q/sPF4
         xni3rVN7pTebgDFRS+FL1VSsC9+CWo4mm8FIM+TRLtEjtYLGr9r9CwTpP5X3TjBYo+IG
         REq5jzJ7MLuZND+BvluNCo81V1/yg91N0UYhrKoaY9Meje7Ubh2oqIK3TKmGjK/LR1I4
         NhaA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=O6mMpLIt;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::536 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x536.google.com (mail-ed1-x536.google.com. [2a00:1450:4864:20::536])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-37d1697ba25si323277f8f.5.2024.10.08.12.38.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Oct 2024 12:38:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::536 as permitted sender) client-ip=2a00:1450:4864:20::536;
Received: by mail-ed1-x536.google.com with SMTP id 4fb4d7f45d1cf-5c91756c9easo240565a12.1
        for <kasan-dev@googlegroups.com>; Tue, 08 Oct 2024 12:38:37 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXBCCcK230C8rLdCZasCoS8od/+tnv4ERYk5CqDUzYBmkLqd9N6zLyOkOkvVNaP+SFCjZgfk20UF00=@googlegroups.com
X-Received: by 2002:a05:6402:1f4b:b0:5c9:11d9:f9b2 with SMTP id
 4fb4d7f45d1cf-5c911d9ff57mr2878883a12.9.1728416316561; Tue, 08 Oct 2024
 12:38:36 -0700 (PDT)
MIME-Version: 1.0
References: <CACzwLxh1yWXQZ4LAO3gFMjK8KPDFfNOR6wqWhtXyucJ0+YXurw@mail.gmail.com>
 <20241008101526.2591147-1-snovitoll@gmail.com> <CANpmjNN3OYXXamVb3FcSLxfnN5og-cS31-4jJiB3jrbN_Rsuag@mail.gmail.com>
In-Reply-To: <CANpmjNN3OYXXamVb3FcSLxfnN5og-cS31-4jJiB3jrbN_Rsuag@mail.gmail.com>
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Date: Wed, 9 Oct 2024 00:39:24 +0500
Message-ID: <CACzwLxhkooTNjijL71AVKm85XChycy1b-Ew11nMbBQWMxNebfw@mail.gmail.com>
Subject: Re: [PATCH v3] mm, kasan, kmsan: copy_from/to_kernel_nofault
To: Marco Elver <elver@google.com>
Cc: akpm@linux-foundation.org, andreyknvl@gmail.com, bpf@vger.kernel.org, 
	dvyukov@google.com, glider@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, ryabinin.a.a@gmail.com, 
	syzbot+61123a5daeb9f7454599@syzkaller.appspotmail.com, 
	vincenzo.frascino@arm.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=O6mMpLIt;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::536
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Tue, Oct 8, 2024 at 4:36=E2=80=AFPM Marco Elver <elver@google.com> wrote=
:
>
> On Tue, 8 Oct 2024 at 12:14, Sabyrzhan Tasbolatov <snovitoll@gmail.com> w=
rote:
> >
> > Instrument copy_from_kernel_nofault() with KMSAN for uninitialized kern=
el
> > memory check and copy_to_kernel_nofault() with KASAN, KCSAN to detect
> > the memory corruption.
> >
> > syzbot reported that bpf_probe_read_kernel() kernel helper triggered
> > KASAN report via kasan_check_range() which is not the expected behaviou=
r
> > as copy_from_kernel_nofault() is meant to be a non-faulting helper.
> >
> > Solution is, suggested by Marco Elver, to replace KASAN, KCSAN check in
> > copy_from_kernel_nofault() with KMSAN detection of copying uninitilaize=
d
> > kernel memory. In copy_to_kernel_nofault() we can retain
> > instrument_write() explicitly for the memory corruption instrumentation=
.
> >
> > copy_to_kernel_nofault() is tested on x86_64 and arm64 with
> > CONFIG_KASAN_SW_TAGS. On arm64 with CONFIG_KASAN_HW_TAGS,
> > kunit test currently fails. Need more clarification on it
> > - currently, disabled in kunit test.
>
> I assume you retested. Did you also test the bpf_probe_read_kernel()
> false positive no longer appears?
I've tested on:
- x86_64 with KMSAN
- x86_64 with KASAN
- arm64 with HW_TAGS -- still failing
- arm64 with SW_TAGS
Please see the testing result in the following link:
https://gist.github.com/novitoll/e2ccb2162340f7f8a63b63ee3e0f9994

I've also tested bpf_probe_read_kernel() in x86_64 KMSAN build,
it does trigger KMSAN, though I don't see explicitly copy_from_kernel*
in stack frame. AFAIU, it's checked prior to it in text_poke_copy().

Attached the PoC in the comment of the link above:

root@syzkaller:/tmp# uname -a
Linux syzkaller 6.12.0-rc2-g441b500abd70 #10 SMP PREEMPT_DYNAMIC Wed
Oct 9 00:17:59 +05 2024 x86_64 GNU/Linux
root@syzkaller:/tmp# ./exploit
[*] exploit start
[+] program loaded!
[ 139.778255] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D
[ 139.778846] BUG: KMSAN: uninit-value in bcmp+0x155/0x290
[ 139.779311] bcmp+0x155/0x290
[ 139.779591] __text_poke+0xe2d/0x1120
[ 139.779950] text_poke_copy+0x1e7/0x2b0
[ 139.780297] bpf_arch_text_copy+0x41/0xa0
[ 139.780665] bpf_dispatcher_change_prog+0x12dd/0x16b0
[ 139.781324] bpf_prog_test_run_xdp+0xbf0/0x1d20
[ 139.781898] bpf_prog_test_run+0x5d6/0x9a0
[ 139.782372] __sys_bpf+0x758/0xf10
[ 139.782759] __x64_sys_bpf+0xdd/0x130
[ 139.783178] x64_sys_call+0x1a21/0x4e10
[ 139.783610] do_syscall_64+0xcd/0x1b0
[ 139.784039] entry_SYSCALL_64_after_hwframe+0x67/0x6f
[ 139.784597]
[ 139.784779] Uninit was created at:
[ 139.785197] __alloc_pages_noprof+0x717/0xe70
[ 139.785689] alloc_pages_bulk_noprof+0x17e1/0x20e0
[ 139.786223] alloc_pages_bulk_array_mempolicy_noprof+0x49e/0x5b0
[ 139.786873] __vmalloc_node_range_noprof+0xef2/0x24f0
[ 139.787414] execmem_alloc+0x1ec/0x4c0
[ 139.787841] bpf_jit_alloc_exec+0x3e/0x40
[ 139.788299] bpf_dispatcher_change_prog+0x430/0x16b0
[ 139.788837] bpf_prog_test_run_xdp+0xbf0/0x1d20
[ 139.789324] bpf_prog_test_run+0x5d6/0x9a0
[ 139.789774] __sys_bpf+0x758/0xf10
[ 139.790167] __x64_sys_bpf+0xdd/0x130
[ 139.790580] x64_sys_call+0x1a21/0x4e10
[ 139.791007] do_syscall_64+0xcd/0x1b0
[ 139.791423] entry_SYSCALL_64_after_hwframe+0x67/0x6f
>
> > Link: https://lore.kernel.org/linux-mm/CANpmjNMAVFzqnCZhEity9cjiqQ9CVN1=
X7qeeeAp_6yKjwKo8iw@mail.gmail.com/
> > Suggested-by: Marco Elver <elver@google.com>
>
> This looks more reasonable:
>
> Reviewed-by: Marco Elver <elver@google.com>
>
> This looks like the most conservative thing to do for now.
Done.
>
> > Reported-by: syzbot+61123a5daeb9f7454599@syzkaller.appspotmail.com
> > Closes: https://syzkaller.appspot.com/bug?extid=3D61123a5daeb9f7454599
> > Reported-by: Andrey Konovalov <andreyknvl@gmail.com>
> > Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D210505
> > Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
> > ---
> > v2:
> > - squashed previous submitted in -mm tree 2 patches based on Linus tree
> > v3:
> > - moved checks to *_nofault_loop macros per Marco's comments
> > - edited the commit message
> > ---
> >  mm/kasan/kasan_test_c.c | 27 +++++++++++++++++++++++++++
> >  mm/kmsan/kmsan_test.c   | 17 +++++++++++++++++
> >  mm/maccess.c            | 10 ++++++++--
> >  3 files changed, 52 insertions(+), 2 deletions(-)
> >
> > diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
> > index a181e4780d9d..5cff90f831db 100644
> > --- a/mm/kasan/kasan_test_c.c
> > +++ b/mm/kasan/kasan_test_c.c
> > @@ -1954,6 +1954,32 @@ static void rust_uaf(struct kunit *test)
> >         KUNIT_EXPECT_KASAN_FAIL(test, kasan_test_rust_uaf());
> >  }
> >
> > +static void copy_to_kernel_nofault_oob(struct kunit *test)
> > +{
> > +       char *ptr;
> > +       char buf[128];
> > +       size_t size =3D sizeof(buf);
> > +
> > +       /* Not detecting fails currently with HW_TAGS */
> > +       KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_KASAN_HW_TAGS);
> > +
> > +       ptr =3D kmalloc(size - KASAN_GRANULE_SIZE, GFP_KERNEL);
> > +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> > +       OPTIMIZER_HIDE_VAR(ptr);
> > +
> > +       if (IS_ENABLED(CONFIG_KASAN_SW_TAGS)) {
> > +               /* Check that the returned pointer is tagged. */
> > +               KUNIT_EXPECT_GE(test, (u8)get_tag(ptr), (u8)KASAN_TAG_M=
IN);
> > +               KUNIT_EXPECT_LT(test, (u8)get_tag(ptr), (u8)KASAN_TAG_K=
ERNEL);
> > +       }
> > +
> > +       KUNIT_EXPECT_KASAN_FAIL(test,
> > +               copy_to_kernel_nofault(&buf[0], ptr, size));
> > +       KUNIT_EXPECT_KASAN_FAIL(test,
> > +               copy_to_kernel_nofault(ptr, &buf[0], size));
> > +       kfree(ptr);
> > +}
> > +
> >  static struct kunit_case kasan_kunit_test_cases[] =3D {
> >         KUNIT_CASE(kmalloc_oob_right),
> >         KUNIT_CASE(kmalloc_oob_left),
> > @@ -2027,6 +2053,7 @@ static struct kunit_case kasan_kunit_test_cases[]=
 =3D {
> >         KUNIT_CASE(match_all_not_assigned),
> >         KUNIT_CASE(match_all_ptr_tag),
> >         KUNIT_CASE(match_all_mem_tag),
> > +       KUNIT_CASE(copy_to_kernel_nofault_oob),
> >         KUNIT_CASE(rust_uaf),
> >         {}
> >  };
> > diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
> > index 13236d579eba..9733a22c46c1 100644
> > --- a/mm/kmsan/kmsan_test.c
> > +++ b/mm/kmsan/kmsan_test.c
> > @@ -640,6 +640,22 @@ static void test_unpoison_memory(struct kunit *tes=
t)
> >         KUNIT_EXPECT_TRUE(test, report_matches(&expect));
> >  }
> >
> > +static void test_copy_from_kernel_nofault(struct kunit *test)
> > +{
> > +       long ret;
> > +       char buf[4], src[4];
> > +       size_t size =3D sizeof(buf);
> > +
> > +       EXPECTATION_UNINIT_VALUE_FN(expect, "copy_from_kernel_nofault")=
;
> > +       kunit_info(
> > +               test,
> > +               "testing copy_from_kernel_nofault with uninitialized me=
mory\n");
> > +
> > +       ret =3D copy_from_kernel_nofault((char *)&buf[0], (char *)&src[=
0], size);
> > +       USE(ret);
> > +       KUNIT_EXPECT_TRUE(test, report_matches(&expect));
> > +}
> > +
> >  static struct kunit_case kmsan_test_cases[] =3D {
> >         KUNIT_CASE(test_uninit_kmalloc),
> >         KUNIT_CASE(test_init_kmalloc),
> > @@ -664,6 +680,7 @@ static struct kunit_case kmsan_test_cases[] =3D {
> >         KUNIT_CASE(test_long_origin_chain),
> >         KUNIT_CASE(test_stackdepot_roundtrip),
> >         KUNIT_CASE(test_unpoison_memory),
> > +       KUNIT_CASE(test_copy_from_kernel_nofault),
> >         {},
> >  };
> >
> > diff --git a/mm/maccess.c b/mm/maccess.c
> > index 518a25667323..3ca55ec63a6a 100644
> > --- a/mm/maccess.c
> > +++ b/mm/maccess.c
> > @@ -13,9 +13,14 @@ bool __weak copy_from_kernel_nofault_allowed(const v=
oid *unsafe_src,
> >         return true;
> >  }
> >
> > +/*
> > + * The below only uses kmsan_check_memory() to ensure uninitialized ke=
rnel
> > + * memory isn't leaked.
> > + */
> >  #define copy_from_kernel_nofault_loop(dst, src, len, type, err_label) =
 \
> >         while (len >=3D sizeof(type)) {                                =
   \
> > -               __get_kernel_nofault(dst, src, type, err_label);       =
         \
> > +               __get_kernel_nofault(dst, src, type, err_label);       =
 \
> > +               kmsan_check_memory(src, sizeof(type));                 =
 \
> >                 dst +=3D sizeof(type);                                 =
   \
> >                 src +=3D sizeof(type);                                 =
   \
> >                 len -=3D sizeof(type);                                 =
   \
> > @@ -49,7 +54,8 @@ EXPORT_SYMBOL_GPL(copy_from_kernel_nofault);
> >
> >  #define copy_to_kernel_nofault_loop(dst, src, len, type, err_label)   =
 \
> >         while (len >=3D sizeof(type)) {                                =
   \
> > -               __put_kernel_nofault(dst, src, type, err_label);       =
         \
> > +               __put_kernel_nofault(dst, src, type, err_label);       =
 \
> > +               instrument_write(dst, sizeof(type));                   =
 \
> >                 dst +=3D sizeof(type);                                 =
   \
> >                 src +=3D sizeof(type);                                 =
   \
> >                 len -=3D sizeof(type);                                 =
   \
> > --
> > 2.34.1
> >

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACzwLxhkooTNjijL71AVKm85XChycy1b-Ew11nMbBQWMxNebfw%40mail.gmail.=
com.
