Return-Path: <kasan-dev+bncBCCMH5WKTMGRB45XWX6QKGQEJJ52L7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id E6C362B0940
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 16:59:48 +0100 (CET)
Received: by mail-qt1-x83c.google.com with SMTP id m17sf2615402qtu.11
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 07:59:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605196788; cv=pass;
        d=google.com; s=arc-20160816;
        b=Da5iyi4kzlAJpwhmuTsI3cokN2ZDc7qungcikW65JEmhQRzu0ZZDYXF8tbZZgk8dCv
         sYPuEEyu9ECVlYL7pl53dTyY5OeXJtjqfTAU8IvVwVtpjc8xDhkr6tnYy5tT0e0UN4Xn
         xl+nDbtvhBQ31DX0Kxm+p1OkoowmLxaFoAQUACTVxP2nC+fEwYMVSUpoNRUZULhMN9pS
         JCeAn1+71EAdLbctt9NDAvX6ZaqN8mHiCBkFBpn+5a+x9r7MjqLEUeD6wBXlBO11NQ3k
         GUMJHz9IX7qgfKDeiu6jCXVXWp9PiX4aUu28cLpzx7b0JWCMBf35LwG3dh1ajxmw9Fx7
         Gkrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SO0dfX/FYFhQ6mK9MbZUU2l0eAksZ1BUPwGW8GX+M2c=;
        b=J+y9KYaN8epCIU0sPgHTGeBc5wt2NJoU2zVLispam94FBdJuJ2njKQABWwio/Geqde
         kHnnwed+KR3ebglen81LGyiHjAp2soatukPoJDeId3QLuBwjvjzFCjH5Sc/qGoE9CDAE
         i6a0BW/Ub2fIpufDkNRhCfXg4JZkNsI+B4bhE4pSrqffI0N/+VwXgnVqM1V4wNihj0fJ
         6cQVuaiwE+NNvoTAa+8wYfZFT+LJm467CdT/tVLieDfCIuwPu0xvP2Y2S5WduXZjicad
         G7Be/Xd0Fh1yyx9vduVJlmYmYlfGIP8udZ7cIz2qgaHMTlTJs0RA9lVNs4gFr0XRx1OS
         /f0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=adOBV9vU;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::732 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=SO0dfX/FYFhQ6mK9MbZUU2l0eAksZ1BUPwGW8GX+M2c=;
        b=Q+ZmzNHMHNu0eL2XElfSAfp6PA/8Z1AS/VXkWE71H6WfQGW/mRK1LIvtK92x0pwNXi
         jje/ULS8MjjyE1JUGp5/opjPAM3+x7YWviJYS9W/O/5fLA3C67D3jG2/2pGqJBaBF5jL
         sQNAP4Bn4vUOIaVH5PvrV8EF0q3bmMbD7n/bP9oFHkIvJ0qzbAlBXwYeKa7o/L4r5E9u
         l3B8J8V06H7/tjv/wBmWnCZrOBW4VhY440udoAPMoy0B0Xmj7a08dPV/G+LBs/Hy1VAJ
         Tw61Q91RJkXjEvVP7qJHrlc7l88dAqNcfQAfe9UXsihEPK3j5SPqIZcVudby4HGw2so6
         wJ9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=SO0dfX/FYFhQ6mK9MbZUU2l0eAksZ1BUPwGW8GX+M2c=;
        b=ly8vYBJh4A2e70S6S/2xOc0XrwJSaNTOwvDRtNcAl/xUHNsNDzqby/kVORgGWu++ZU
         M2e3EOpKCaAQBPiaJCFOKMO6gfZiLlpeG8gI0Kvi9jEhi/QgoNR6691+oKq6FlOInUpV
         pBIRDUtrHjkdSZEnLL4GlFycCHf17AFVNtVIWCpal6ZVPVwoQ/BBRSKLWntyyFTSpSv9
         30kTz8amT4e0D6WVvZ4jqkZH8dexo3IpDNxIq7Lzosa0m4zXW7mjtU+K9SrHPRxT5ZVM
         SM38p07dIHK0KmEzoKDZrZSAbjuQNox7bAXerpUBtGXc5Igwg53u/jOzGP/11LireFF5
         RKIw==
X-Gm-Message-State: AOAM533Gl4Na+wk+equCPF/VBNDFuJ8G4RQCZklzlwCmTySc9MvcIy+S
	12K/+rTGIJWHu4fsar1aeZw=
X-Google-Smtp-Source: ABdhPJy/JaMztv0Fw+krfHExav67yWeZok4r6xWZicgfePcO9Qw68Kq0H3we49050WUq3WVDESUnfw==
X-Received: by 2002:a05:622a:4e:: with SMTP id y14mr21926349qtw.392.1605196787837;
        Thu, 12 Nov 2020 07:59:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:7006:: with SMTP id l6ls1502509qkc.5.gmail; Thu, 12 Nov
 2020 07:59:47 -0800 (PST)
X-Received: by 2002:ae9:ea0a:: with SMTP id f10mr468664qkg.164.1605196787330;
        Thu, 12 Nov 2020 07:59:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605196787; cv=none;
        d=google.com; s=arc-20160816;
        b=cVLnoby4ow0PQAePZD2uaFAUSMH7Fa1l/aLlR0kCgxI/gd3/PZwklVz0jTBoTZ06u/
         il+CSHN/Z7NQhwg1NMY1TDPQc1nV/iIix23zrlytkT3IKNgYxKvl9YIP++XmVkt7gq8K
         gTOFXnhTaW50KVUJ0FXzypm65bq9gaH03kDzi8frMQQRK1Zsun8bqfBBR1LiDx7BxTCN
         kM9VXXujCJpJ5dZLf6R1XQr5wm/P0E6oADb8XdIKTiAd8GZvODEsdBXrRxgC0siNLOEH
         2IkZ4IVxvHfldSSh6qjvK9Xl36Gf83cpyDtRyhfJfEdkSHHAkAj6Q4iJ2MEbJZ+G4dRl
         RMDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=4jCOmZMfeGT0TXCdgSotnEbRECtZNT/yP78oj9y32ro=;
        b=iEUkQfEkkccV7alay6NY/gaO5e8GG+Yhz2YH282WCxPQq+SMMxOYtZkLjvDL9T0nrb
         oOxoWfmASHkJ6Q7l7VA1SKa8ERsb/ebfA1Dkte5KCWkrNnABt9Ob6SOL0t2UkrwhhxfU
         DUfgyZnU7/IneA+9q8YJLc9XdtGG91N35/3WnM1O92H9N3HYcQ0+jkcF8UdhmD7z1O0U
         OOuAuvL+r0IovnVfL/iNF5o35zSLHbSG9N/Mb2MhMuLRn2Zv/Ryl9A0I6QOQ2cMcLAdR
         YR0sN3Lh6e2OM6G4qRWVwoLLJh9VF4zZjGD4fXDY+1Moc707pqOXkpJJdQxgbjh8ahkX
         6d7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=adOBV9vU;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::732 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x732.google.com (mail-qk1-x732.google.com. [2607:f8b0:4864:20::732])
        by gmr-mx.google.com with ESMTPS id h1si461656qkg.5.2020.11.12.07.59.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Nov 2020 07:59:47 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::732 as permitted sender) client-ip=2607:f8b0:4864:20::732;
Received: by mail-qk1-x732.google.com with SMTP id l2so5707166qkf.0
        for <kasan-dev@googlegroups.com>; Thu, 12 Nov 2020 07:59:47 -0800 (PST)
X-Received: by 2002:a05:620a:211b:: with SMTP id l27mr441705qkl.352.1605196786695;
 Thu, 12 Nov 2020 07:59:46 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <bd6825832c0cb376fc68ad61ffec6d829401ed0e.1605046192.git.andreyknvl@google.com>
In-Reply-To: <bd6825832c0cb376fc68ad61ffec6d829401ed0e.1605046192.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Nov 2020 16:59:35 +0100
Message-ID: <CAG_fn=XpB5ZQagAm6bqR1z+6hWdmk_shH0x8ShAx0qpmjMsp5Q@mail.gmail.com>
Subject: Re: [PATCH v9 44/44] kselftest/arm64: Check GCR_EL1 after context switch
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=adOBV9vU;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::732 as
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

On Tue, Nov 10, 2020 at 11:12 PM Andrey Konovalov <andreyknvl@google.com> w=
rote:
>
> From: Vincenzo Frascino <vincenzo.frascino@arm.com>
>
> This test is specific to MTE and verifies that the GCR_EL1 register
> is context switched correctly.
>
> It spawn 1024 processes and each process spawns 5 threads. Each thread

Nit: "spawns"


> +       srand(time(NULL) ^ (pid << 16) ^ (tid << 16));
> +
> +       prctl_tag_mask =3D rand() % 0xffff;

Nit: if you want values between 0 and 0xffff you probably want to use
bitwise AND.


> +
> +int execute_test(pid_t pid)
> +{
> +       pthread_t thread_id[MAX_THREADS];
> +       int thread_data[MAX_THREADS];
> +
> +       for (int i =3D 0; i < MAX_THREADS; i++)
> +               pthread_create(&thread_id[i], NULL,
> +                              execute_thread, (void *)&pid);

It might be simpler to call getpid() in execute_thread() instead.

> +int mte_gcr_fork_test()
> +{
> +       pid_t pid[NUM_ITERATIONS];
> +       int results[NUM_ITERATIONS];
> +       pid_t cpid;
> +       int res;
> +
> +       for (int i =3D 0; i < NUM_ITERATIONS; i++) {
> +               pid[i] =3D fork();
> +
> +               if (pid[i] =3D=3D 0) {

pid[i] isn't used anywhere else. Did you want to keep the pids to
ensure that all children finished the work?
If not, we can probably go with a scalar here.


> +       for (int i =3D 0; i < NUM_ITERATIONS; i++) {
> +               wait(&res);
> +
> +               if(WIFEXITED(res))
> +                       results[i] =3D WEXITSTATUS(res);
> +               else
> +                       --i;

Won't we get stuck in this loop if fork() returns -1 for one of the process=
es?

> +       }
> +
> +       for (int i =3D 0; i < NUM_ITERATIONS; i++)
> +               if (results[i] =3D=3D KSFT_FAIL)
> +                       return KSFT_FAIL;
> +
> +       return KSFT_PASS;
> +}
> +


--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DXpB5ZQagAm6bqR1z%2B6hWdmk_shH0x8ShAx0qpmjMsp5Q%40mail.gm=
ail.com.
