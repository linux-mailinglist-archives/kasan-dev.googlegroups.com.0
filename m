Return-Path: <kasan-dev+bncBCU4TIPXUUFRBGPFSSAQMGQEAXY4CDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id C591E318C1A
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 14:35:22 +0100 (CET)
Received: by mail-yb1-xb3e.google.com with SMTP id g17sf3494464ybh.4
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 05:35:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613050522; cv=pass;
        d=google.com; s=arc-20160816;
        b=CSeEXBUn6ZwJhCpwFWK3AXiB/GvMOoDO8H39+NmYHriXuATTApuhPOvkZkHD1JZ4j/
         K2ftyz0bgtmf0IgTTDiFPmZZploC4qxrmANq8gHZHd0u1sRrenbEneuAM4w497zgLMW+
         MzRTDhevLaYlZoeRLFkJCthl3XUwcGhYWy6zZxUV2bczHfBNe4uLZ4iBlLrvzEvCtwVY
         S0KvkUcyEUgcHxn7KOfj59mV0QFE5yKs8d7C4lB6nHK5ikfHg1tm8GzFXzttR+0cTNbw
         JtMx0QjpVS5LBp/0JdSYaO960O3d+0geDtTxvGBANjddHN9ibw8uV3YF463m2gAwyZ2n
         zuOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=9H8megrAocdO1JKIAsuDIntR4HNTr39hdq7liRj485s=;
        b=RmMAjMcFDDSJ/650wGSjm34XolYLsxd+ml8VSsn4LX1GOkbaArxpD1C1SXjvSCzdpk
         CVu/yjL3eTcL42KMaM5YBb6dYQ/LzLeN5rsyVD6+Pkxa7vuFoCWP6RFB+ZJTyF7YpEBW
         sYNC3NRYiyNewjudrCskyDZ6jclmEZ8f1GCsoOU3O/iYXB0mfyJd+USxjwyq1cJHxzsL
         tTTpu5nCKRIh+cHu9B7e5WtdyehrAM758eJp0Zthqhk/j2Jx+IW9copun4fQIVIyV3Jx
         dT9cBGO8JkQEZIhVgqRDXH9GuXRgce/8VemTy7NymYaXofLN+yH1fptJO+Fn/HsZsZRr
         KD6A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="Su/T1oN8";
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9H8megrAocdO1JKIAsuDIntR4HNTr39hdq7liRj485s=;
        b=hxD9n2y8sv4Dgn/cblrgcHb8Hf3D4mSs5fAEb4cL/8/NnGhStnIC4iLhzPj2yHYKrY
         O+MO/RA8mbai3L3NDGxwHAHjdmXovE6/OnL/p2hOiv/UTO9LywUXvBewNGlHYxDBObnT
         eRJ4jn1c5pDxsrPWblIsNbYvOXlck5vIU2V03liKrmPboAD9QIiLr94asJGoxGcbA5hi
         oNKsQZqMZi+i5B/ibAcpSvwFsrLc3YShu4Cx0mFFr9dSN/V/JA9SnUGEwuzqv4wGTren
         GBotBBAtkpnzp1e36K72fayxmFbod+EUduqrlBZnOFSz1SauMRzrosJWzWe2HCiCg/nE
         qlow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=9H8megrAocdO1JKIAsuDIntR4HNTr39hdq7liRj485s=;
        b=oxZfnIHxMAqx5mrPwdVippgXKBY7KKACNgC3gXzJv3hjLgiJr+Be6NrN0TtTHIkhjk
         641S980ELYaRy46T87hCeuaUbf0V/Oru7nTXBkABQVgsrL69tgwQu4pRSjBA0XXX9I/p
         mCnP7Gy8KBQItvRm8ZFDqN5XmfUO2Etsli/mcl8ffN0DfPYxSvKXVBoBHh1igpp+h2Fl
         80m3jdIKQq8Tpuwnl7OhBT7OUEBIrOXrGou5BilrjPKApfqpRmbCEo1JppI6ZSxXKwzj
         C5WdU6BM+aGb6NPk1n+4VNbvoxn29D1CmrRcyfXEdPxXqsawhv8LQZi/jFCTW9CjC2pS
         YmSw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Um/VxyTdtGk5/jNtqNZhi10VEUm/Sl1y1rI5wmYndhepH1WvO
	sqDtBrXRzPQThEdv61MCeEM=
X-Google-Smtp-Source: ABdhPJx/WOQO7vh0GGPHUoMp6giU4bPHdlxdePO09G0QcAHkNs7LZjNY8qC/gdamJoadIwwLKFQ3vQ==
X-Received: by 2002:a25:da0e:: with SMTP id n14mr11532020ybf.356.1613050521779;
        Thu, 11 Feb 2021 05:35:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:8b88:: with SMTP id j8ls2610352ybl.3.gmail; Thu, 11 Feb
 2021 05:35:21 -0800 (PST)
X-Received: by 2002:a25:cbd5:: with SMTP id b204mr10678946ybg.411.1613050521399;
        Thu, 11 Feb 2021 05:35:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613050521; cv=none;
        d=google.com; s=arc-20160816;
        b=jhcWgRgXceUPQMj7c11RkSaH2SrrAaRlAvsOKj9tiKbXwsuJ3k40M1HmDW9Yyg0Phu
         HGMFSetpyxwA3xTatbGV8R8DCM7BQvpOv25lj+q1sH6YzwX8RrLyWJKWBfjZ2uTQFMJa
         NfWug1gCewxLo1D5b+22/7mKE80k1+1XXgG93DwBn0A4jhqi7Zch0hftwMNR+t4nUwDG
         68f0yo0Qh/n0TPsrH4gJOQuZPwQjbvCVFi/zq+3HBPvVfFqsbUqkPlarPF88EjHeLnxO
         79w8yVi7ovdnvAGoMJ6mbzw2Y+S8uEVKI8Vc0/Qxo27BrRqPECd+EDMQZ6hrdE4zX/6f
         8lgg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=uDebkfyf7sPqQG2Qcb/9O1FSKN5fI4k0f0bzNCuIeMk=;
        b=XvUyjOv66KcPIvWzV82bPj5+pA+BlYfrldouW81JYYOzhHuLfjFf7DiQIZdhwspCVT
         uNupcXhRoMOq0pbxHyFWYfZ6m4vDbO0ndrzdsCAF9mIgd8QZGwYzXc0uwr0Le8cGDg6z
         1jIxMJjRpunLA7wFHLPkZMmqV7DnTJhWeAguD7EEGZHFZAv7AgSyof/oghH9AOqBo2iY
         pCYxjcMpUT02g9it0O3AHniBhymGCVeurd5VUGN7fHp17xxCdKvXXyAIK2v4BQtaw492
         HO0F8PM3lXEv8bL8O4G7m64lRXyJfllnly7UwrGeFFsPLXVygKtzTMRJXVkKDAtP1S5E
         UeIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="Su/T1oN8";
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id d37si408770ybi.4.2021.02.11.05.35.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 11 Feb 2021 05:35:21 -0800 (PST)
Received-SPF: pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 3304664E92
	for <kasan-dev@googlegroups.com>; Thu, 11 Feb 2021 13:35:20 +0000 (UTC)
Received: by mail-ot1-f41.google.com with SMTP id i20so5120165otl.7
        for <kasan-dev@googlegroups.com>; Thu, 11 Feb 2021 05:35:20 -0800 (PST)
X-Received: by 2002:a05:6830:1285:: with SMTP id z5mr5686918otp.90.1613050519509;
 Thu, 11 Feb 2021 05:35:19 -0800 (PST)
MIME-Version: 1.0
References: <20210211125602.44248-1-vincenzo.frascino@arm.com>
In-Reply-To: <20210211125602.44248-1-vincenzo.frascino@arm.com>
From: Ard Biesheuvel <ardb@kernel.org>
Date: Thu, 11 Feb 2021 14:35:08 +0100
X-Gmail-Original-Message-ID: <CAMj1kXHED=O4uXzRAKiD8kE1Vb3Dr=oU-shLQ8UBBDn2N-1nuA@mail.gmail.com>
Message-ID: <CAMj1kXHED=O4uXzRAKiD8kE1Vb3Dr=oU-shLQ8UBBDn2N-1nuA@mail.gmail.com>
Subject: Re: [PATCH] arm64: Fix warning in mte_get_random_tag()
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Will Deacon <will@kernel.org>, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: ardb@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="Su/T1oN8";       spf=pass
 (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=ardb@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Thu, 11 Feb 2021 at 13:57, Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> The simplification of mte_get_random_tag() caused the introduction of the
> warning below:
>
> In file included from arch/arm64/include/asm/kasan.h:9,
>                  from include/linux/kasan.h:16,
>                  from mm/kasan/common.c:14:
> mm/kasan/common.c: In function =E2=80=98mte_get_random_tag=E2=80=99:
> arch/arm64/include/asm/mte-kasan.h:45:9: warning: =E2=80=98addr=E2=80=99 =
is used
>                                          uninitialized [-Wuninitialized]
>    45 |         asm(__MTE_PREAMBLE "irg %0, %0"
>       |
>
> Fix the warning initializing the address to NULL.
>
> Note: mte_get_random_tag() returns a tag and it never dereferences the ad=
dress,
> hence 'addr' can be safely initialized to NULL.
>
> Fixes: c8f8de4c0887 ("arm64: kasan: simplify and inline MTE functions")
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Cc: Andrey Konovalov <andreyknvl@google.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>
> This patch is based on linux-next/akpm
>
>  arch/arm64/include/asm/mte-kasan.h | 7 ++++++-
>  1 file changed, 6 insertions(+), 1 deletion(-)
>
> diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/=
mte-kasan.h
> index 3d58489228c0..b2850b750726 100644
> --- a/arch/arm64/include/asm/mte-kasan.h
> +++ b/arch/arm64/include/asm/mte-kasan.h
> @@ -40,7 +40,12 @@ static inline u8 mte_get_mem_tag(void *addr)
>  /* Generate a random tag. */
>  static inline u8 mte_get_random_tag(void)
>  {
> -       void *addr;
> +       /*
> +        * mte_get_random_tag() returns a tag and it
> +        * never dereferences the address, hence addr
> +        * can be safely initialized to NULL.
> +        */
> +       void *addr =3D NULL;
>
>         asm(__MTE_PREAMBLE "irg %0, %0"
>                 : "+r" (addr));
> --
> 2.30.0
>

Might it be better to simply change the asm constraint to "=3Dr" ?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAMj1kXHED%3DO4uXzRAKiD8kE1Vb3Dr%3DoU-shLQ8UBBDn2N-1nuA%40mail.gm=
ail.com.
