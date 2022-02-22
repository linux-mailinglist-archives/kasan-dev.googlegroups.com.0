Return-Path: <kasan-dev+bncBCXKTJ63SAARBXPV2KIAMGQEN35JEGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0F3BB4BF5CC
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Feb 2022 11:28:47 +0100 (CET)
Received: by mail-qv1-xf3b.google.com with SMTP id if3-20020a0562141c4300b0043147d6bacdsf9852386qvb.13
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Feb 2022 02:28:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645525726; cv=pass;
        d=google.com; s=arc-20160816;
        b=LCawDTwFnhCYkRebQ0ckRQmbUzgLNqg3fxjDy7RgTEU9/BeDaIcl/y3gV14G0MmEGE
         eacdnSszNQwLGJEzo0O1XCkBKpbtq9UgK9OmH8wFfdDpuI2CeXmVrHFNd8n43QmMA+FC
         FGngAv0TltyVqSDLjNNrja7GxHfRFOjFK2SJUTAHKZAI/BY6M7twjeDb5ZzL4P7rtc1S
         4w6G8hynIEnD9qKzcl8oZ3Vu4CoiEJz7jENkYg0GDYS39/fw60hdzGH8ruBHMd+fqeUr
         +r/J51GIfgwxlko3mstPhMgp/uhVvrGBzweoRWhwgSPu45NEMq1+JXH6HZiO8U5YGhXa
         PTeg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=WIRI9BbPs2ZOusTdJ1ZIIelBb6vY7FYc8eOVJBY49o0=;
        b=Jmmimg+oXagXqsKtDM+Ei7VLkolXyBBnK5Pp4JY5AzCB891Gh+Sqs0eYe/U8JpQgWL
         vuHfAYFH08+WZadibtO052Bxj/qLASPsJNomRAw2BjtOKhWBVe3OLV4KmwfZU1nyjfuu
         l4qbzppqVg5i2gneaMu7128rTU/dB3NQy6FkXTzP8sCfZL4XgrWoICWaQMy3er5BMpUf
         v5Of66r0unhbEnSjhiEOdR6ET/soBxxmZQQvjDoe2fnwyKfb+vGjUhShd6aSeJeHAd0U
         k3+GaX449L2bysDqqMLLXrMHg9vopdj0QhIMBkcPoav76/wMZlKFFHp7r5zHtdvxhR3V
         ST4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DLkDqBLd;
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::133 as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WIRI9BbPs2ZOusTdJ1ZIIelBb6vY7FYc8eOVJBY49o0=;
        b=SpPzRBLVzy1xYYHAQDEE4SHwZv/3wczd1qnFEcL75jr/6ycdibg4hpVuesxwV4qchn
         ThIRUUI+hQOEVBEqc/zRyCAG0QoQu35yC+lncq7ExoJFjPUTOCFpFB1dd1W6olsNq3M6
         0WqCBQP9q+bFsSEklKbM4X0HAObeeU/4IeuHfBfxBTqCWPDIMn9NVmwKH49gFn0IAYR0
         xtZuXFOI40yRWx8QPgeR947cr0XzE+J7lZJk5JINnK9uQ0xIMcQB/7r9IefUujioFaOV
         59JMQt2FHjBE0pI0c6+ltbQ8xPz1W6iSrjPFRa8It4ac3IaOqPKTaXp9Gsm69yrraQi8
         Zizw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WIRI9BbPs2ZOusTdJ1ZIIelBb6vY7FYc8eOVJBY49o0=;
        b=BzXOGIjoc12WSVEAiMNMTJz56kEFtE5h2iye1rX23rs/ddcQIBcZYRXdWCfk5Mbb27
         8aDl/qehQ7b1BcwZrm5aGPLKl78hu4GcWpnzNZBdLp1kroq9IwQNvIRzG+SBM/M9JUkE
         hdPwgJ0Ec0qi12+svtYD0KoJ15Vox49vyhjQPEp/EYlNfca+9nVq8brIzCzLJMoWM4d4
         5Y9AR+te14O1eAArZhvnr0wKqJBmI0olmzTzxL5AxhZ48OcOp0o7e01i7VOHlHoKNoa9
         JeL7X6A7c6zvCBwjBqUiV+uelRVFO0caqxJegJiEHNPS/YzPy/25QSk+6RqY5VwoM+23
         wb0A==
X-Gm-Message-State: AOAM530TaixSSHYYPaYvthSKexlwZgO6OmVuWu7Wkx9HAf3uTKBJgKVK
	qyyYmHu3Aj4su0ZlK9C2SRk=
X-Google-Smtp-Source: ABdhPJwYfMSPIrYkPK7PbiNmb4hi7B+txOsKe3ZOKmw+NQ0dz8zhz4BGO1QyLTZ/RG/L06NniL9wyQ==
X-Received: by 2002:a05:622a:93:b0:2ca:c95a:543 with SMTP id o19-20020a05622a009300b002cac95a0543mr21637576qtw.674.1645525725765;
        Tue, 22 Feb 2022 02:28:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:256:b0:2dd:d879:1c2c with SMTP id
 c22-20020a05622a025600b002ddd8791c2cls6159749qtx.5.gmail; Tue, 22 Feb 2022
 02:28:45 -0800 (PST)
X-Received: by 2002:a05:622a:1903:b0:2dd:a07e:659e with SMTP id w3-20020a05622a190300b002dda07e659emr17565819qtc.360.1645525725354;
        Tue, 22 Feb 2022 02:28:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645525725; cv=none;
        d=google.com; s=arc-20160816;
        b=GpdH5UpeNNzCMxDV1K5Sm4X4iOTA85m6wo2+2Igz3x+jxVlAh4Jbnv5+7r7FQOPlnM
         mMHR4XRfHnxVgDhn3WQsVo30G25NYU4qokCTlkXo8Zb5VOH4Qz6pQyYc7wx3H/VzaOAt
         7sNYgySaCwFaYtC4hRuxo1uol7C3063//6xnYqyRPuhxqx6PSA8jRx8f1UwTcEYXEOp/
         i2/JY/4EUs1p2xTS6vWvf7HR+GevFxZkMu7H5pYSa4s70y3ZzojiJPvAPMle7vq4f5J+
         UuOPHwqlto9zO8iMZtIMjK/HH9nc0CODjYXfu3J1FQ04BxHL10D9qXeU1c2adunuL2vl
         uq1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=eS2A2SDIO/vp8PmlyWTYQFrSZtShYqNTX+yWJ9M+0YE=;
        b=gKKnGLQ9XOIADqwvaas8Pfe4UgczecnHDI9Dovl36Dy8H6wNh7KTvPqTMzhsZufbon
         dokG4h5/NjMP7w3Fnr9vqhvDDD7F/Ku2lfCIP8S/rejuQjppawIZHGUsPRB+/8/LWK6g
         6e6MkMALoNiCQ+RGxiUthALW7FlVfpwFr3eTur88rmUkdCVHq1zexjGytJxOhL17RxpU
         0R/C+3NBmUL5m4+D+cci2gow+TDNBPHiG2JCjVaZ4l7xCRtaUGJu5u4kQYb/uvtUtgm/
         X7kl4OKf+11zksrhfjCGm31MUsNaNCnBo7dXx/fhJVrCo1BstAcRmVks/a/ZdjJ4/fIn
         Sg+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DLkDqBLd;
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::133 as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-il1-x133.google.com (mail-il1-x133.google.com. [2607:f8b0:4864:20::133])
        by gmr-mx.google.com with ESMTPS id bi42si579098qkb.2.2022.02.22.02.28.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 22 Feb 2022 02:28:45 -0800 (PST)
Received-SPF: pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::133 as permitted sender) client-ip=2607:f8b0:4864:20::133;
Received: by mail-il1-x133.google.com with SMTP id v5so2129621ilm.9
        for <kasan-dev@googlegroups.com>; Tue, 22 Feb 2022 02:28:45 -0800 (PST)
X-Received: by 2002:a92:c241:0:b0:2b9:80f9:e2a with SMTP id
 k1-20020a92c241000000b002b980f90e2amr19663534ilo.208.1645525724716; Tue, 22
 Feb 2022 02:28:44 -0800 (PST)
MIME-Version: 1.0
References: <20220221161232.2168364-1-alexandre.ghiti@canonical.com> <20220221161232.2168364-5-alexandre.ghiti@canonical.com>
In-Reply-To: <20220221161232.2168364-5-alexandre.ghiti@canonical.com>
From: "'Aleksandr Nogikh' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 22 Feb 2022 11:28:33 +0100
Message-ID: <CANp29Y7M=wSLBE8m0-CHKtYPkqgcxNiUPEyRNv-VHeR5O2BTYQ@mail.gmail.com>
Subject: Re: [PATCH -fixes v2 4/4] riscv: Fix config KASAN && DEBUG_VIRTUAL
To: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Nick Hu <nickhu@andestech.com>, 
	linux-riscv@lists.infradead.org, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: nogikh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=DLkDqBLd;       spf=pass
 (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::133 as
 permitted sender) smtp.mailfrom=nogikh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Aleksandr Nogikh <nogikh@google.com>
Reply-To: Aleksandr Nogikh <nogikh@google.com>
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

Hi Alexandre,

Thanks for the series!

However, I still haven't managed to boot the kernel. What I did:
1) Checked out the riscv/fixes branch (this is the one we're using on
syzbot). The latest commit was
6df2a016c0c8a3d0933ef33dd192ea6606b115e3.
2) Applied all 4 patches.
3) Used the config from the cover letter:
https://gist.github.com/a-nogikh/279c85c2d24f47efcc3e865c08844138
4) Built with `make -j32 ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-`
5) Ran with `qemu-system-riscv64 -m 2048 -smp 1 -nographic -no-reboot
-device virtio-rng-pci -machine virt -device
virtio-net-pci,netdev=net0 -netdev
user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:12529-:22 -device
virtio-blk-device,drive=hd0 -drive
file=~/kernel-image/riscv64,if=none,format=raw,id=hd0 -snapshot
-kernel ~/linux-riscv/arch/riscv/boot/Image -append "root=/dev/vda
console=ttyS0 earlyprintk=serial"` (this is similar to how syzkaller
runs qemu).

Can you please hint at what I'm doing differently?

A simple config with KASAN, KASAN_OUTLINE and DEBUG_VIRTUAL now indeed
leads to a booting kernel, which was not the case before.
make defconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
./scripts/config -e KASAN -e KASAN_OUTLINE -e DEBUG_VIRTUAL
make olddefconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-

--
Best Regards,
Aleksandr

On Mon, Feb 21, 2022 at 5:17 PM Alexandre Ghiti
<alexandre.ghiti@canonical.com> wrote:
>
> __virt_to_phys function is called very early in the boot process (ie
> kasan_early_init) so it should not be instrumented by KASAN otherwise it
> bugs.
>
> Fix this by declaring phys_addr.c as non-kasan instrumentable.
>
> Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
> ---
>  arch/riscv/mm/Makefile | 3 +++
>  1 file changed, 3 insertions(+)
>
> diff --git a/arch/riscv/mm/Makefile b/arch/riscv/mm/Makefile
> index 7ebaef10ea1b..ac7a25298a04 100644
> --- a/arch/riscv/mm/Makefile
> +++ b/arch/riscv/mm/Makefile
> @@ -24,6 +24,9 @@ obj-$(CONFIG_KASAN)   += kasan_init.o
>  ifdef CONFIG_KASAN
>  KASAN_SANITIZE_kasan_init.o := n
>  KASAN_SANITIZE_init.o := n
> +ifdef CONFIG_DEBUG_VIRTUAL
> +KASAN_SANITIZE_physaddr.o := n
> +endif
>  endif
>
>  obj-$(CONFIG_DEBUG_VIRTUAL) += physaddr.o
> --
> 2.32.0
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANp29Y7M%3DwSLBE8m0-CHKtYPkqgcxNiUPEyRNv-VHeR5O2BTYQ%40mail.gmail.com.
