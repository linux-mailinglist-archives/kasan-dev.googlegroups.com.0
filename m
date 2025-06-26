Return-Path: <kasan-dev+bncBDAOJ6534YNBB3NG6TBAMGQE5LGLZ2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C6BFAE9A05
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 11:31:29 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id ffacd0b85a97d-3a4edf5bb4dsf498787f8f.0
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 02:31:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750930286; cv=pass;
        d=google.com; s=arc-20240605;
        b=bHL5LvI1zDD4PtVZleB2hUFEyBFO6J+l8jvFh1LvNMCOuQTvCRy2PNp3j6Go2LWIui
         2KvJMLVDEyFByv2DHTl4N/FpVPAhKc+vLR/jqQR29NG7CyHlTakclQA4MHEdnA78Or2E
         F7FI8JtfV45RjYDIgBwVTxsZJolGelVQwNwy20iARFFe2slYToYZzEVviYOcbuuTuNy9
         jvRDW3UJwQMwZvDquYO77XNRBassEp3eq+HH10a9V70H5oPhRJwCf19Wd9rrJuvfJ86D
         RD51ggqIWwVf0bK9Li3U9NY7K5RsuqOUDw8maHMpEjWUjTg+dfOscUiJy9xID4iiBVlT
         DNfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=LibQfcsi/vVA/e7ezhZCSjS/EUHiIaz3zoB4HyFmuDM=;
        fh=QRflh4nvggNN1NTm2Y8g1R9wOmwifDdHrManOwO1nHM=;
        b=bRUKDjnZqct8g7ZHgx5ls/Df+GaJPWm8diN78TxDlhrnG5GsS8MnTB+xHRslYWP/p9
         Wn5UQ50L44OOErFIQmk4D+p5YEbZ9oU+U/xmVRZkSFyuGifmikjdYRrdLYNsp45I41is
         gB7jl4YOsbG6RwX4ZLMA6ldHzJiry9MnbmIK5RcS8/K0/p9BV/FqL6GmxLcQivbT9IW0
         veW7IpPeHCwlvRcpvCFgRDoGmf3kWPaNgS+UbKlsjNyKYgeGP0CEXLL/3HPDnX9yKlcz
         YUIrHYhyWv9hXnYQF1NGAsyDJU2VY4oS0W2E3MJDjTYWH4EQs3pgyBmYmUjpTj2UtSea
         XDpQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Wyo7eDm3;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750930286; x=1751535086; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=LibQfcsi/vVA/e7ezhZCSjS/EUHiIaz3zoB4HyFmuDM=;
        b=KD3cV6gqq3W0Z+y49ZyQOwnBGqgxBzh/aeO/30vJZOJVhVbhHWuh2jcAZYKUCJHfj7
         unX0JuDFTWYCfDzGFL2NTCyQNn5BMtoHStkvAN+nugcKXofThq38USbAfqr/NpR3ECOn
         Qr/C6+DUQSUSppF/21bvEM39He4VF2V0t1W3jtPROVNr+ZuVLq/Sgvq1HABBORUiFV0M
         udry7KZCQUVr7nsZvxpdnGa1iNqvakR6BLHvBfGfgPbw5OU4YTEZEIF01zrTJ/qpMBPJ
         rjwVTK0Vp/Yd3KOy/tMocUMcFIminF3o49h+esq4sscpuahw/llKkRvBsvAIX/I05OMp
         xysQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1750930286; x=1751535086; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LibQfcsi/vVA/e7ezhZCSjS/EUHiIaz3zoB4HyFmuDM=;
        b=JK/HrPPBgWk5/V9mMfAinSpbVJicGbIgLfBkuxX2YeunLZODXk9jTCquMuYnf1iMM5
         7Cr9J9CZSufVjH6jEpJ28nqdyxqajLTjFb4Wjvwc83aAWj+PG42gDqXOS4k9UGBGRfKB
         V/okK/mSWQpa1ycQoePU5g8pWRSh4in85Vbeqq+YiumRtyTAXN72LjKgEKGUGs+RmB/c
         gQ79dQ/v3833qBSeojJ/PzDadCKLcIxCp7+ITTHhiMaySWvktz3c1Jn2d5z9fw0ZdfjU
         H52vJDcazmoX7dJSLdJzu+uG/yOjBSj/mMuE2EQkqmmNlEfDbG5w3krjvfueSaFCRMtL
         T6ow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750930286; x=1751535086;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=LibQfcsi/vVA/e7ezhZCSjS/EUHiIaz3zoB4HyFmuDM=;
        b=Ijdl0VKBnPg8MXweyd8PevmkSkSWGJfLLhEREcJU1dZieCqNhDLgiGaWAziPuiq2Kd
         GkZtpG3z+K8TVvBKt2AfWBl3QYPn1scoQWM1W0OQpzPpyztoQcxLpVA+us+VtEYdnNun
         CA8K2qgqfDjxTY/n6zPvMkeTAnD9XdtnCmdUmiV770FSEDmAheJdBSKpYl8MPg5qq+6d
         CEvOFgvJhd7tvxevG5aWRGkGEJvI7kxY3BtHexzHUvPSpprShv5aZ7uwfn+W6P23YC5s
         fjR8c47mzTL0OPTJwRzrdRnbXWmRFB8wgQHvoW4Pjw1TU54sC9VdbAL8TPpUzAATgM8V
         YzAg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXkzV8iixHAMUliCWTdhHyb7F0PfmLXcnkR28XRk5Q8VYvaFg0EP2Jg420UF6yNDO1pD8qjXw==@lfdr.de
X-Gm-Message-State: AOJu0Yy95JBtswL/MdXKi8p0VzzZYH/dbLGhJ6tlrJZj1hHGQplW2hvh
	OxBb8lw/HkNa89a01LDG1rgEh243B87OLNlIzn8c4iVBLX9kZJnBzfbh
X-Google-Smtp-Source: AGHT+IGFYk4mulZApOpzp2HWhbslmVtyh7wlT4M0YOEwhlNl4FNDjXZIp8KVe2NcPkcuh0ZP4oxJ2w==
X-Received: by 2002:a05:6000:2a0b:b0:3a4:f513:7f03 with SMTP id ffacd0b85a97d-3a6ed646f6dmr4370000f8f.44.1750930286345;
        Thu, 26 Jun 2025 02:31:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeVNJRKK6LiIUw8vBItCODkSKmHoyi+faqskjGx9MB4gQ==
Received: by 2002:a05:600c:3545:b0:43c:ef03:56fa with SMTP id
 5b1f17b1804b1-4538a20fd18ls3688325e9.2.-pod-prod-02-eu; Thu, 26 Jun 2025
 02:31:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVlMj24T2riFvfUl+Z0T6yk6wz1lSLAMnJugw03tZjJuhNtParyoGi2dgcUsZOSp3rCty1amCBmxEM=@googlegroups.com
X-Received: by 2002:a05:600c:8b2a:b0:43c:ed61:2c26 with SMTP id 5b1f17b1804b1-45381b0f38fmr68272255e9.17.1750930284028;
        Thu, 26 Jun 2025 02:31:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750930284; cv=none;
        d=google.com; s=arc-20240605;
        b=dKJnEBtVUPVPgdmFZZZxLZ9Kh7iSgKZjP6f+M+vgjjZR5F+MfZJpoIvVD8qGYaOEvY
         wvqcrlrIROFllfLrunRakybNs2yBtSL/QwjEApwL5+vg0NKMD6dxN7dl1WLMtkxRwyW3
         sC/24aVIK9PF33qprE/5lL4dNuf9pWbJme9M/WmqpnXxMjiFb271/kV4t/ck+34UsV4Y
         0xflm5as7wqIA2dTNLs5GjqwzSm8rOosIXeevAF3OCxpr+EU5wIZBPBX0Fl8p6ARpRKn
         VOVOcm0V9dryVTkTAzHrR4q1N4TOVQT2wPAPmS/uRXYsk/l4YaJWPS3A3uSqAqaG5ZIU
         Xcfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=iuFmqpRengejqXGMt8z0krXQLsPU94kcoziX8PACH+I=;
        fh=oyOA1geuqdaubbRVBTirT0QB7IKD+cTF8X5n0UpaFsg=;
        b=OXHrJgWwMbBeQ/PMmanW5T2sri2NYGnKnzrcE2VDHsx0rcKTKi3DmjqHK1Co1IMfrA
         buzayBjavUm8aryBOhPgZcsOfFzzdErZpCmifVNC2UJlz8VySRi+f5olizFsEm3062a4
         vQGMB33NK9v536KXpq+klT7nridAzON+bEdNW9ig3HORpWVDB3cxHhJxkuGGVNkpTlbN
         FIcT4JAtVRUrJdRUBWTAgvfYlDVE/wedmz8fegILLXMFtAvPq3mUHhyiik81PMomOngO
         HkprX732ZuEsrklFDVoZxF2/HQMDH1nwxRIsLTtFxAwn7NM3xLT5TFDVkgufcNPyndj8
         S3Gg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Wyo7eDm3;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x133.google.com (mail-lf1-x133.google.com. [2a00:1450:4864:20::133])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-453814a4debsi1002675e9.1.2025.06.26.02.31.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Jun 2025 02:31:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) client-ip=2a00:1450:4864:20::133;
Received: by mail-lf1-x133.google.com with SMTP id 2adb3069b0e04-553644b8f56so739414e87.1
        for <kasan-dev@googlegroups.com>; Thu, 26 Jun 2025 02:31:23 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXoJSMETTE5SanLh1fXV8dFhUngcQWyhxIbvfFnUELFErnEPMPd+i+00o+u3WPnuCemgT/VIIahK80=@googlegroups.com
X-Gm-Gg: ASbGncsK1OtnppzPEEUVBOhPaL0jwnfA5kFt2Ow8iOOt1W0DR97GYGt8te/5YN0HyAn
	n61HlSeoI6J6d+uw+QcrxhmWfocWs0zliUH8ufqky+OW5XUkI05qSORBrdoDTPFk3mjS10MlX4f
	fUWrIuIDp2Z0AANQmVgg+s1oZ76DJANCmxutvu9VRqVt6sJlpoC/hh
X-Received: by 2002:a05:6512:1150:b0:553:36b7:7b14 with SMTP id
 2adb3069b0e04-554fdf96ec2mr2102615e87.37.1750930282937; Thu, 26 Jun 2025
 02:31:22 -0700 (PDT)
MIME-Version: 1.0
References: <20250625095224.118679-1-snovitoll@gmail.com> <20250625095224.118679-2-snovitoll@gmail.com>
 <db30beb6-a331-46b7-92a3-1ee7782e317a@csgroup.eu>
In-Reply-To: <db30beb6-a331-46b7-92a3-1ee7782e317a@csgroup.eu>
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Date: Thu, 26 Jun 2025 14:31:05 +0500
X-Gm-Features: Ac12FXyxTyp0b2hD3uhdVzbeUTYpXnyKRANJYa2mQoNch15i1MQX1xBLZECmC3k
Message-ID: <CACzwLxj3KWdy-mBu-te1OFf2FZ8eTp5CieYswF5NVY4qPWD93Q@mail.gmail.com>
Subject: Re: [PATCH 1/9] kasan: unify static kasan_flag_enabled across modes
To: Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, 
	dvyukov@google.com, vincenzo.frascino@arm.com, catalin.marinas@arm.com, 
	will@kernel.org, chenhuacai@kernel.org, kernel@xen0n.name, 
	maddy@linux.ibm.com, mpe@ellerman.id.au, npiggin@gmail.com, hca@linux.ibm.com, 
	gor@linux.ibm.com, agordeev@linux.ibm.com, borntraeger@linux.ibm.com, 
	svens@linux.ibm.com, richard@nod.at, anton.ivanov@cambridgegreys.com, 
	johannes@sipsolutions.net, dave.hansen@linux.intel.com, luto@kernel.org, 
	peterz@infradead.org, tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, 
	x86@kernel.org, hpa@zytor.com, chris@zankel.net, jcmvbkbc@gmail.com, 
	akpm@linux-foundation.org, guoweikang.kernel@gmail.com, geert@linux-m68k.org, 
	rppt@kernel.org, tiwei.btw@antgroup.com, richard.weiyang@gmail.com, 
	benjamin.berg@intel.com, kevin.brodsky@arm.com, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org, 
	loongarch@lists.linux.dev, linuxppc-dev@lists.ozlabs.org, 
	linux-s390@vger.kernel.org, linux-um@lists.infradead.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Wyo7eDm3;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::133
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

On Wed, Jun 25, 2025 at 3:35=E2=80=AFPM Christophe Leroy
<christophe.leroy@csgroup.eu> wrote:
>
>
>
> Le 25/06/2025 =C3=A0 11:52, Sabyrzhan Tasbolatov a =C3=A9crit :
> > Historically the fast-path static key `kasan_flag_enabled` existed
> > only for `CONFIG_KASAN_HW_TAGS`. Generic and SW_TAGS either relied on
> > `kasan_arch_is_ready()` or evaluated KASAN checks unconditionally.
> > As a result every architecture had to toggle a private flag
> > in its `kasan_init()`.
> >
> > This patch turns the flag into a single global runtime predicate that
> > is built for every `CONFIG_KASAN` mode and adds a helper that flips
> > the key once KASAN is ready.
>
> Shouldn't kasan_init_generic() also perform the following line to reduce
> even more code duplication between architectures ?
>
>         init_task.kasan_depth =3D 0;

I've tried to introduce a new function kasan_mark_ready() to gather
all arch duplicated code in one place:

In mm/kasan/common.c:

void __init kasan_mark_ready(void)
{
        /* Enable error reporting */
        init_task.kasan_depth =3D 0;
        /* Mark KASAN as ready */
        static_branch_enable(&kasan_flag_enabled);
}

So we could've called it
in mm/kasan/generic.c:
void __init kasan_init_generic(void)
{
        kasan_mark_ready();
        pr_info("KernelAddressSanitizer initialized (generic)\n");
}

in mm/kasan/sw_tags.c:
void __init kasan_init_sw_tags(void)
{
...
        kasan_mark_ready();
        pr_info("KernelAddressSanitizer initialized ..");
}

in mm/kasan/hw_tags.c:
void __init kasan_init_hw_tags(void)
{
...
        kasan_mark_ready();
        pr_info("KernelAddressSanitizer initialized ..");
}

But it works only for CONFIG_KASAN_GENERIC mode,
when arch code calls kasan_init(), for example, arm64:

void __init kasan_init(void)
{
        kasan_init_shadow();
        kasan_init_generic();
}

And for HW_TAGS, SW_TAGS it won't work.
Fails during compiling:
mm/kasan/common.c:45:12: error: no member named 'kasan_depth' in
'struct task_struct'
   45 |         init_task.kasan_depth =3D 0;

because kasan_init_sw_tags(), kasan_init_hw_tags() are called
once on CPU boot. For arm64, where these KASAN modes are supported,
both functions are called in smp_prepare_boot_cpu().

So I guess, every arch kasan_init() has to set in kasan_init()
       init_task.kasan_depth =3D 0;
to enable error messages before switching KASAN readiness
via enabling kasan_flag_enabled key.

>
> Christophe
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ACzwLxj3KWdy-mBu-te1OFf2FZ8eTp5CieYswF5NVY4qPWD93Q%40mail.gmail.com.
