Return-Path: <kasan-dev+bncBCQ6FHMJVICRBUFNUX7AKGQEBQMBXWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id E7EF02CE07D
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Dec 2020 22:21:21 +0100 (CET)
Received: by mail-ot1-x33a.google.com with SMTP id w1sf1671165otp.21
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Dec 2020 13:21:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607030480; cv=pass;
        d=google.com; s=arc-20160816;
        b=WhQrTCM6ufGFIbyfyQshANDsMbQSLlPW/GOiPvZ9/Vr58FiArUCNI84Wdwz3wtgUk/
         yf1OFnIkPjOTlOms+rhKKikr/hgA6EwLJOcMpRqQ87syjZ9SYtGmuesrVALaM+vQ09uw
         B3Zvu9roVUZjwha9Yx3PeVoukqBjjyynnskyZ4GQ+bWmeXzWPeFRjgl3LKLzaCWrLJUc
         EwYlJbZkyQviDcj1qAmksGHNOAJKCxrkQRHSYZGgBG24iP9yWQWETSWQrD8AcyQA84xT
         JWvarMI0ZH4eADnxeUruyc9+8WYu4s1AonX6bYE/Czvd6SKNMK1Vzi6vIDoeLm6z5PgO
         3InQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=b0Q1kN4J+TJ8ULL+tKjoaIhNwxrr7iUuVZXijLTVJOM=;
        b=ZJxVxec+mN7zPilr3pZfp4YzD4MayRXjDA/vP6QvblEjWONSq6ncVFs7EdUee2Imve
         PHnOL3tQs2VjIdYyV/gAmzGH8VdoXFTtnmfKHRajguGJu0WGvSZpDtsR4+w1X9FYACo2
         tH82abAaR7xbtEtp1MjXdZm04qo60aTHXcUSJA1FW/1yngVz6k2K/WE3UCB8t9VqtFOW
         y4bgtb7mqx689DSMpHJlQwpXijr+cVAeHdVnRkU5BXaqL9IKd5GNCCNelZHUE00YCUE3
         V2pLVRCJQbtxfNiJ/dwOD/mbkC7jiVYftrRIsCD0vO/OkCZS0sHvzaCLNxDzQmvR8yPh
         Sh4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canb.auug.org.au header.s=201702 header.b=MKA70ro8;
       spf=pass (google.com: domain of sfr@canb.auug.org.au designates 203.11.71.1 as permitted sender) smtp.mailfrom=sfr@canb.auug.org.au
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b0Q1kN4J+TJ8ULL+tKjoaIhNwxrr7iUuVZXijLTVJOM=;
        b=H0JGXI7ZthlRTly4G3My/Jhw3U7Na1gzLSMG+lSMV8fKA3Y0QDxzx5+3mhKVW6SvRg
         12zveEvNCDDnEBfGCwg0oVb9houTqK+yciNhK8AR16YbY37Rcwsww08j8PvaB2zchyv+
         NAb+rCNE8i/yYmkqol2culrmGv2e1iGx87k9ktU3dyDTCiaX2hvwcax8lcGeqQWF42Zt
         wQ4eL0rT6KhErEvOO+lvDHYNQJbfeKLQYaY6n6EAdOeaNETo6UTSXoTKnoGbefyR46yh
         RVxG0rZIMOQqqzU88YCcVm2mX6PSGnOh2U8voYzw1z257KJ55U0neO/kH59whUjp9NhY
         pFUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b0Q1kN4J+TJ8ULL+tKjoaIhNwxrr7iUuVZXijLTVJOM=;
        b=ke2WOTAuhLd4ZiTmUdi1MZ7/TMbm7Nop69eO63Lmp3rO+f9+frOh/6UyGRkNRoNm1N
         7p8OS9w9ZmAKxixuG/D5TbMrA52ucvoygPUFjWIrXwKeme+nr+LxdkG0w9mW23lVhrY5
         /uAkXg0979b5Fzz4BqWmviF+7MrqmoSI+gsNubjA02L/CFMEF/7nNEIwxUgbXQHwedU9
         jS8052eJq07cUu+TrR2izXxjYJO3NbJwAIYlWRFRP/i+W+xE5dhDBdVYaPolp+MZdUFP
         KGJ2F66JOgFbxhrBj9D/+90ge+7cnItOkzcKiwRj7GIHdGBXg6smSt87RUYfLLhAoYQK
         SYXw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530zZDpTeq5mq5Ct2pcFieHCMvDGJu7yp3zFiXLweNpAmWW4hCUw
	nb5Os3tbQ4mUugKK/MfJDq8=
X-Google-Smtp-Source: ABdhPJxs27YbuLgIJNV/stTlfQaiLE+J55lQ6C2gA6kdvhUoTPzdsHHyqUWRksCh8/FV+2LSI5w26g==
X-Received: by 2002:aca:fd0d:: with SMTP id b13mr774357oii.27.1607030480836;
        Thu, 03 Dec 2020 13:21:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:a843:: with SMTP id r64ls1818253oie.2.gmail; Thu, 03 Dec
 2020 13:21:20 -0800 (PST)
X-Received: by 2002:aca:919:: with SMTP id 25mr741273oij.95.1607030480372;
        Thu, 03 Dec 2020 13:21:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607030480; cv=none;
        d=google.com; s=arc-20160816;
        b=VIdtpZhcN7aNjfGM8Og8+uw8sODxqlh+vR3saTILAVmBvmGOqw5j4nTGB7EZT45Jan
         g9tm/kwwpRhhY0etNU+GX/hQGYN9fG+4++lHlGXROVvJZ16H/lVfKK3s6DeOZHlVu3Uw
         ExzJBNDhYVMYtxfK+lmjc6QWLrX5u0lr7XBPjZk2f8huNZcZ6ZgRhz+tIqtM+HYA2XAF
         J+jecgHRznta3N4ZS4C98dGjMZ9cRkknB5tTu6l6iL64f4DAhCKugQWrlNfIOlRUB3/w
         EetLCg59IbPOCo3oX7DBZkmBzwgrePIyET+T77FG3M1drDAXAaJHopjZu1Ih+3EE/uv+
         r50Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:subject:cc:to:from
         :date:dkim-signature;
        bh=ZijW8FQ3xy0821HjHoB+/2NyzCPHW0MLNdcyuQRr6w0=;
        b=P+yG7oy3d7djwIDzRKd68eeA9rFUWVe2EfHCSK1nwEN65rV4x8Ygq7/Heaxzqxymfx
         ZH0eYJ0kpiRYh9nxbV3Iv+KXx9Ng9duKEjopC9oYVDgDzWtLhEDvkigeynWrclKLE0D7
         +c1EN/0RjnP08TpC1otqbf+MUdNYxUy1Ts55sZqyjDo5M9bVh0Zz4pw3OA+S1xfMaFOu
         95N1/7W8kUcoYW26tdrZrVs37ToU5C3add11DlvmJ91Yydp25p55449cjVzaVl7DDyfP
         JjzYJjc0UTRWhxtC24u3X61qy/5h3FdnxjFDCdobxZZkQ2ose3LdKizgd+2ICScC8hEK
         1haQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canb.auug.org.au header.s=201702 header.b=MKA70ro8;
       spf=pass (google.com: domain of sfr@canb.auug.org.au designates 203.11.71.1 as permitted sender) smtp.mailfrom=sfr@canb.auug.org.au
Received: from ozlabs.org (bilbo.ozlabs.org. [203.11.71.1])
        by gmr-mx.google.com with ESMTPS id l192si51492oih.3.2020.12.03.13.21.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 03 Dec 2020 13:21:19 -0800 (PST)
Received-SPF: pass (google.com: domain of sfr@canb.auug.org.au designates 203.11.71.1 as permitted sender) client-ip=203.11.71.1;
Received: from authenticated.ozlabs.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by mail.ozlabs.org (Postfix) with ESMTPSA id 4Cn8092Nqjz9sSf;
	Fri,  4 Dec 2020 08:21:13 +1100 (AEDT)
Date: Fri, 4 Dec 2020 08:21:12 +1100
From: Stephen Rothwell <sfr@canb.auug.org.au>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrey Konovalov
 <andreyknvl@google.com>, Catalin Marinas <catalin.marinas@arm.com>,
 vjitta@codeaurora.org, Minchan Kim <minchan@kernel.org>, Alexander
 Potapenko <glider@google.com>, Dan Williams <dan.j.williams@intel.com>,
 Mark Brown <broonie@kernel.org>, Masami Hiramatsu <mhiramat@kernel.org>,
 LKML <linux-kernel@vger.kernel.org>, ylal@codeaurora.org,
 vinmenon@codeaurora.org, kasan-dev <kasan-dev@googlegroups.com>, Linux-Next
 Mailing List <linux-next@vger.kernel.org>, Qian Cai <qcai@redhat.com>
Subject: Re: [PATCH v2] lib: stackdepot: Add support to configure
 STACK_HASH_SIZE
Message-ID: <20201204082112.331df654@canb.auug.org.au>
In-Reply-To: <20201203123253.c00767545ad35c09dabd44ef@linux-foundation.org>
References: <1606365835-3242-1-git-send-email-vjitta@codeaurora.org>
	<7733019eb8c506eee8d29e380aae683a8972fd19.camel@redhat.com>
	<CAAeHK+w_avr_X2OJ5dm6p6nXQZMvcaAiLCQaF+EWna+7nQxVhg@mail.gmail.com>
	<ff00097b-e547-185d-2a1a-ce0194629659@arm.com>
	<55b7ba6e-6282-2cf6-c42c-272bdd23a607@arm.com>
	<20201203123253.c00767545ad35c09dabd44ef@linux-foundation.org>
MIME-Version: 1.0
Content-Type: multipart/signed; boundary="Sig_//jXIelCd6/S1dNu7qWlVKto";
 protocol="application/pgp-signature"; micalg=pgp-sha256
X-Original-Sender: sfr@canb.auug.org.au
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canb.auug.org.au header.s=201702 header.b=MKA70ro8;       spf=pass
 (google.com: domain of sfr@canb.auug.org.au designates 203.11.71.1 as
 permitted sender) smtp.mailfrom=sfr@canb.auug.org.au
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

--Sig_//jXIelCd6/S1dNu7qWlVKto
Content-Type: text/plain; charset="UTF-8"

Hi Andrew,

On Thu, 3 Dec 2020 12:32:53 -0800 Andrew Morton <akpm@linux-foundation.org> wrote:
>
> Thanks, all.  I'll drop
> lib-stackdepot-add-support-to-configure-stack_hash_size.patch.

I have removed that from linux-next today.

-- 
Cheers,
Stephen Rothwell

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201204082112.331df654%40canb.auug.org.au.

--Sig_//jXIelCd6/S1dNu7qWlVKto
Content-Type: application/pgp-signature
Content-Description: OpenPGP digital signature

-----BEGIN PGP SIGNATURE-----

iQEzBAEBCAAdFiEENIC96giZ81tWdLgKAVBC80lX0GwFAl/JVsgACgkQAVBC80lX
0Gw1hgf9GxZkiaL2ZpuXpM7GTSfCax9pLRKqdOp4MNPSb2Q5C6Rl4JmD2/1kYl5l
THZNCqEdiLZ7SUyxy/9RykfnqjrILfkMcbbjM/mJPce3xJpBqFaWDMgtDjeCI1gI
Um/aOqwuG0bFAhcCFt7ZvMaI8Tl6P9pY/nP6N38TVt6qLnn4yqzdyyuxvetJ5nOH
Mni3HX2dBZoYkeyNuayI2Z0ayya5pNQlL2f94bjQaIQ3Lb8AHr7Jv5PHgsEPHz7O
T+EZaqDajaAyLyN65YCCkSN8zVvsKE60Qt2yeb7V9wbjM9cYy9HD5DsiAH3DbZLZ
1kg4KWdYbTMRT2yJcudcrpaTXdPnvA==
=P5DX
-----END PGP SIGNATURE-----

--Sig_//jXIelCd6/S1dNu7qWlVKto--
