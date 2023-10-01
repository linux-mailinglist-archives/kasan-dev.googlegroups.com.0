Return-Path: <kasan-dev+bncBDW2JDUY5AORBPNR4SUAMGQENZ44MWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id E0C067B45B7
	for <lists+kasan-dev@lfdr.de>; Sun,  1 Oct 2023 08:59:10 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-35231e92df4sf33790265ab.2
        for <lists+kasan-dev@lfdr.de>; Sat, 30 Sep 2023 23:59:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696143549; cv=pass;
        d=google.com; s=arc-20160816;
        b=ckQ9CzjBTC6K87ujNodcEnVEwpNbg2X593mxYhzGmNkavs6divLX8/tOqurZ8t3m82
         iyDjZHPKOXPLAt3N57HVEUTE7Pt39GKJy3k5tOzNHQdjA6S0+vCn6Xkb3KSe2ncgi10i
         bT6swjvEpun2eW8a7wjBaCioBjW6fJUpS9+rcQfZ/Vq52a9vZfcV6oHcpO8059sPkB1H
         Z6Lj5/OaVk6kyoaqR3D5eiE7Vb2YzoFDi5h/hK4sewDqcKbwmaHDaiurNLk9q8qU0ijQ
         afmjdU9NfyJ8UQ6jhjChVOnZqVTx9NbrVbF9iXgIVcSsE2x+rRLxAg0nJaI6fqAOGHaD
         6Gyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=IoHXo+C7Zl9cYTjc8U4/h8neUQpc7MRY0mQrqglrKUA=;
        fh=70TMYxp65vvEwzXuylvgPjbByhBlOrPKRhrMDNQLBrg=;
        b=hBY6NraTA/ul2oGHatwr44ViWrg4j5y0bNd9SpAmsRJRbe6UmibuUOT0gkD1qrulv1
         4X7w6IomryUn/MPIOtL7sFPCObXl2WGGELH695bKACEHa+tOOaWs9+N2QlfMn8TE/tHb
         OlxzzOCBEivBrNVbcNAXWa/wPyPU+ncjoNlwpFKnee05T7R2QrtdyoIowhONqZZ/NMtM
         EMooDTALzJSlhoqyM8XCwt4UpRxkTH5P9FvI00ri0JEjsKBRuJPJvyKiafZ8c+YXIGHu
         RtlwG+b5FdxMteU2qJt1k7IbQ0kb5fQ+TssASfyS0bdSTrfRcy7YOueJCiOtlJF1/9VI
         oNdQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=V5ZYNJ28;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696143549; x=1696748349; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=IoHXo+C7Zl9cYTjc8U4/h8neUQpc7MRY0mQrqglrKUA=;
        b=W3ThX8Qi2a/6N7Dtm4C1Fq/SD/pFsBPmhFjYRzEq4ocYQeHQSOlJQKPzzh2NtKr221
         WS4ku9+rixZP4UtsaoizMqVmN4ky50hh3mlqRMAgqB37hid65fT9vpmL9bnA0z2vSUki
         FKGh6/GixCybXrMvEDdssxJimCD7V62Bnd7QdJw03yTY4mN4rxAHVnwofZiTMcApodfr
         uyeuDrflblR/n7RoA3WK4Z/8x//7jFHrmbiibt2wFpVkrPf5g+qFk7sM3EpRMLC7vdT/
         6TxdLBZ+UgVebfEgwhbhdV7IBXhmlPcCWjIfo4WqaFp47bhJSH9qxldKviVTr9dwLGUe
         14zQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1696143549; x=1696748349; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=IoHXo+C7Zl9cYTjc8U4/h8neUQpc7MRY0mQrqglrKUA=;
        b=YtZhEf+8RH4c0HXsRI3Azrks5uo4FYk99WlHir9XOvDg+SAMznjub3m+s99/+yTloi
         gY5pLSbMD9fOU5WMK/5h09rqgoTtUw7f6RszM8IEEdlO2Y/qM3/tEb7WYSghKkIT5sAB
         NJogxL0RDpT9C28uL0vOA3zzm7GUjyQjHCZzjPDbKjU66QzC7j86wlsx86jltnR/vmYv
         IguUE55lejh5HgprIT1kXHnpIx/evaYqp4FaCDd771zN3yo4h3VkX4P2eCwGRtDpaM3i
         kdzVFJsdMi81rQlTecLt2WS+eLZ2q5EO7AqSXX3Z4+dtTotXxcUgKrJOPS/LXCUErHIq
         aJ3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696143549; x=1696748349;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=IoHXo+C7Zl9cYTjc8U4/h8neUQpc7MRY0mQrqglrKUA=;
        b=q+9z6U/OoVlOB4tezNqofaPU8eyZ2LibhjoRXbLsfKcqNRrZUsc4p5TgVpv4wVnudx
         iGdCO+3fS9h89JUJSxoeAHdaoWBmL2D0EP47xDhxkBFM9wEKO4BGyUp/4ERsgwdUZjAa
         HReYEj95zg4B6m2mOdOK2egyI+fSTlz7SkG2OZLDIJGjdvTuRqpqzpY6V1sqOyLFh1DP
         gNWeO+sF2h6Hq7x2kjOJNCxBOtwjkdLkAqafxkmHrhQQygysL2dgNgOjcOqpYEU/z/Ai
         Fd4JOXG6YqLsEmswlxi+gGAejpjsZ3a2OndkdO7nhHdSCsPM7OCCHzW7H+V3FKYW+bT/
         68lQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyZRe3Gy6t9ry8Tayc5HXAOW1S7piXyLEztqTTwsaTbLpWMKnZh
	cgGnZw9OGUA/MUzMKeTQuy8=
X-Google-Smtp-Source: AGHT+IFlIKQR4EwGPHEUhNEXm0cnNfj7m0arrz0EkKfTYFYeJGLt6BxJjRVKxUWDHqHzkE69kGUErQ==
X-Received: by 2002:a92:d4cb:0:b0:34f:77bc:8d49 with SMTP id o11-20020a92d4cb000000b0034f77bc8d49mr8008061ilm.23.1696143549389;
        Sat, 30 Sep 2023 23:59:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:3f0f:0:b0:349:3346:c3e0 with SMTP id m15-20020a923f0f000000b003493346c3e0ls3106344ila.1.-pod-prod-09-us;
 Sat, 30 Sep 2023 23:59:08 -0700 (PDT)
X-Received: by 2002:a92:d4cb:0:b0:34f:77bc:8d49 with SMTP id o11-20020a92d4cb000000b0034f77bc8d49mr8008031ilm.23.1696143548422;
        Sat, 30 Sep 2023 23:59:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696143548; cv=none;
        d=google.com; s=arc-20160816;
        b=aDocRqTh11p6H6a03DpFt4NFj3vDvXQnOBBc6BTjAt+Vn30lKWzxDyFcHhMsHLxEKB
         7IbP0e6IIvU4PYnw/zVZ+7ORQpwSNdZBP/nPxWxRE/A/hu6bv61RThA+PYKENKdav0CM
         a2B8UDL2ud6K8LMYihOZwZiJAxUuQz2CA/7BHMKQbd3Vgybvf7yGMwEgDrSZZqPzJWWG
         uIQqOEvxbBWOyiYq4GuqrgPuRLa/wupMqQlG0QE7T9fQYEy6HpoyOaXTsaBiJXWtIyHI
         FAPBkNSQ/oBk2i6kkp6bGzNP4Zq0A3gvEB668c5PI6AtnYGrCqOqCvPBj9ecPkieQkT3
         77CA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=iFogJBniBFn6caNvLOi/GkfLB5jlxKmfjfT3DU/VTrs=;
        fh=70TMYxp65vvEwzXuylvgPjbByhBlOrPKRhrMDNQLBrg=;
        b=zEPqJ41GS7/OVG3NwyW3LsHQiPJCzBc9MCBVicy+jBFsQHI4qs426rMUM4+C7/D6jI
         i9LxZXHpIMdSPhMFWMlO3kB7GNNTg7Rr24lgNZJGOGjUa1aI3ZTGoUxVMPt6xAh/Jeu7
         py00gLSeL+F8I1qCG7luoyIM4nYImEQNQsqQSq7QVwvpOWiEQgjwhXrlxM8AULYrklSP
         LtH7Pl8LJea+C4DDUxbTwP4bmR6nd0f1cZbwULGKcBBMUsOgXDvu1z6+vH7KpijqlFq3
         1NpqzoKjD0JzOsLA6F0cGXi1eNeFYbLm+hTqoceRr1oI0TF3np/4cPJCULgeDTKKd9qa
         sWbg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=V5ZYNJ28;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qv1-xf33.google.com (mail-qv1-xf33.google.com. [2607:f8b0:4864:20::f33])
        by gmr-mx.google.com with ESMTPS id l13-20020a170903244d00b001c618811ffbsi1049230pls.6.2023.09.30.23.59.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 30 Sep 2023 23:59:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f33 as permitted sender) client-ip=2607:f8b0:4864:20::f33;
Received: by mail-qv1-xf33.google.com with SMTP id 6a1803df08f44-65d5a6230fcso18992826d6.0
        for <kasan-dev@googlegroups.com>; Sat, 30 Sep 2023 23:59:08 -0700 (PDT)
X-Received: by 2002:a05:620a:f81:b0:775:66c1:7f94 with SMTP id
 b1-20020a05620a0f8100b0077566c17f94mr7526632qkn.39.1696143547468; Sat, 30 Sep
 2023 23:59:07 -0700 (PDT)
MIME-Version: 1.0
References: <20230928041600.15982-1-quic_jiangenj@quicinc.com>
 <CAG_fn=V9FXGpqceojn0UGiPi7gFbDbRnObc-N5a55Qk=XQy=kg@mail.gmail.com> <CAK7LNASfdQYy7ON011jQxqd4Bz98CJuvDNCUp2NRrHcK29x3zA@mail.gmail.com>
In-Reply-To: <CAK7LNASfdQYy7ON011jQxqd4Bz98CJuvDNCUp2NRrHcK29x3zA@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 1 Oct 2023 08:58:55 +0200
Message-ID: <CA+fCnZe809yDRNQ_sQHenOE8idBDLDk_p=PG1-_O2NK7bMVxwQ@mail.gmail.com>
Subject: Re: [PATCH] kasan: Add CONFIG_KASAN_WHITELIST_ONLY mode
To: Joey Jiao <quic_jiangenj@quicinc.com>
Cc: Alexander Potapenko <glider@google.com>, Masahiro Yamada <masahiroy@kernel.org>, kasan-dev@googlegroups.com, 
	quic_likaid@quicinc.com, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Nicolas Schier <nicolas@fjasle.eu>, linux-kernel@vger.kernel.org, 
	linux-kbuild@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=V5ZYNJ28;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f33
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Sat, Sep 30, 2023 at 12:13=E2=80=AFPM Masahiro Yamada <masahiroy@kernel.=
org> wrote:
>
> On Fri, Sep 29, 2023 at 11:06=E2=80=AFPM Alexander Potapenko <glider@goog=
le.com> wrote:
> >
> > (CC Masahiro Yamada)
> >
> > On Thu, Sep 28, 2023 at 6:16=E2=80=AFAM Joey Jiao <quic_jiangenj@quicin=
c.com> wrote:
> > >
> > > Fow low memory device, full enabled kasan just not work.
> > > Set KASAN_SANITIZE to n when CONFIG_KASAN_WHITELIST_ONLY=3Dy.
> > > So we can enable kasan for single file or module.
> >
> > I don't have technical objections here, but it bothers me a bit that
> > we are adding support for KASAN_SANITIZE:=3Dy, although nobody will be
> > adding KASAN_SANITIZE:=3Dy to upstream Makefiles - only development
> > kernels when debugging on low-end devices.
> >
> > Masahiro, is this something worth having in upstream Kconfig code?
>
>
> Even if we apply this patch to the upstream,
> you will end up with adding 'KASAN_SANITIZE :=3Dy'
> to the single file/Makefile.
>
> I am not convinced with this patch
> since this nod is not so useful standalone.

Yeah, I agree here, I don't think this change belongs as is in the
upstream KASAN code.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZe809yDRNQ_sQHenOE8idBDLDk_p%3DPG1-_O2NK7bMVxwQ%40mail.gm=
ail.com.
