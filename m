Return-Path: <kasan-dev+bncBD6MT7EH5AARBNFER2DAMGQEVTEHRYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 972D73A46A9
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Jun 2021 18:41:24 +0200 (CEST)
Received: by mail-ed1-x538.google.com with SMTP id s25-20020aa7c5590000b0290392e051b029sf11145118edr.11
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Jun 2021 09:41:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623429684; cv=pass;
        d=google.com; s=arc-20160816;
        b=YYtBPXSflVRkSaXxYc0q5mycywuAbFhhlIYT+GChwtL2ivyDUJ+nyoB0I5SztoQkQQ
         CGaBEh/EeNxzm+seqtGyqemTpmdohtGoMviKhKsIaqKAxGT07yVahst3RIKksOlehxAA
         h5TKm6DgjMK0IwEuKTaSiimIuCYYjDfJzbHzC2kH7VW2414x4GTkBfcCY0RziHx5tug8
         Jab3U/5HnbbtzJv18XYlWw/gfw28IXlJTy8pgpCPjmJfyPgig9HnfvX3BqgDOTvdwsrE
         ZK8xGXBHjOJgNmAQWu0cNUKRIF82dMPHjPQ48ZtdGRO3KYVoch91buWpIK4+3m6BQ+f4
         RiuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:message-id
         :in-reply-to:date:references:subject:cc:to:from:sender
         :dkim-signature;
        bh=/RxueFksMZupNVfPRJD5+U/VMBgYrFZuU3khOE3dsS0=;
        b=ckQa9xZHjp9WW/Qmcwd9HkwOTsTDPnm7IPLCGn4gZw5uKcoszcc3JQYdFHbtN77Ba4
         KX/3N7bBKk5x0EjGzsnB36ogRhfS8X3LO7LdageQjb1yS14hzKgQFPyBAAYhMOr1LXpG
         AiCXNR4X3CdEaHyVzUdM8uRQJNhiAaE9SFs3DVbwdiPxIAYoEQJDQxDhVB1ptD8DOtnU
         rH1YUznLXRuSZt4T97UQB9jY0PVp1J4JUHvFTR5camm5kIdGOjjYzPv2+HwajFCCYFU2
         vAAm6uYg2+IZBYEL29XHsH2RX6hnv+OK4SyG9rH1pkowQTI08HAWKqw97in/8O5A5RS9
         0wlA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of whitebox@nefkom.net designates 2001:a60:0:28:0:1:25:1 as permitted sender) smtp.mailfrom=whitebox@nefkom.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:references:date:in-reply-to:message-id
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/RxueFksMZupNVfPRJD5+U/VMBgYrFZuU3khOE3dsS0=;
        b=Zl6J0qRJBIzFYxBEuQTpv6nPjzCPJf92gL2T8f6sKSE3RmRCSd9gGt+cTVEp/oKLyV
         JfY1Zf8sK6iU4HWoO81Jco3ZikvVbxnddzqrCXfP6HU4rmxvmPseEu70l43bYqr4iGT6
         FVTW/wOjIZ01jLQyzEQ722hcfAt7V7XILzYAei8t89e0yBbX5jPIACHSA0CQVfAHqQIk
         wJ5hjNB0P6w8Nb/1ljUZPNYSEYWMPrHDuxTFItLAS+akl1QJsxlSoL4G9GHs+NJ8hOvE
         fQXWdts4PRMaZLo4aoSVikGOlBBVCxY822seGLbod6LHKihh9n7metrI4rbV3IWVgGF7
         Dkig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:references:date
         :in-reply-to:message-id:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/RxueFksMZupNVfPRJD5+U/VMBgYrFZuU3khOE3dsS0=;
        b=k7zrhJOCj/QnvuJfeJGkM0eqsFMjMJ3Rq+8noLd8XJUYxME22uZzVPEu5d4/1mqHg8
         g067TZSIW9QXE0+8SDCcXYixbG3xNc6VTbiP4mUpg9FnELxssQo9LS9rSY5yA0XHO5C1
         mtNwt+qkqwHqJSZJH1Eod+p3AMc2hVCent2RoY8gck/7ODdAW+ivOFUNnxvNESAj2Yik
         GHhwAN9DajrCL14ht6+aiZ/evYKRBAHsa87RuicyBYo/OIuMn1MXOseM/QXetnFT0Rqo
         pEqACWw684zn8e21cs4tHwI5VEZOMwhenVXWobjzxs6pzFOqd+N0ZwlAu4LC/abDMCwK
         ZRAA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530TFwwGz+yfxeh8UV46+BpLWOnuOt9dxc63huTN/RF9skcfXEH/
	WDXFJUkLjqrcb4WyvDaYHnQ=
X-Google-Smtp-Source: ABdhPJwOn9DJykHId3X8Yjsa6EQarovQ2EZ5Du6gVbVnR9DOcw/MYYvU3jmSEp2/6ZHGzrzvcT6Cyg==
X-Received: by 2002:aa7:c7cd:: with SMTP id o13mr4709131eds.269.1623429684379;
        Fri, 11 Jun 2021 09:41:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:fa91:: with SMTP id w17ls381542edr.2.gmail; Fri, 11 Jun
 2021 09:41:23 -0700 (PDT)
X-Received: by 2002:aa7:d5d6:: with SMTP id d22mr4665238eds.302.1623429683527;
        Fri, 11 Jun 2021 09:41:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623429683; cv=none;
        d=google.com; s=arc-20160816;
        b=ns6D5acrFvxYmu8YKDkuBzNW+KuGLpY9zTt4DJkgEoHhZV1rTtF+euYTByfBAFNkhr
         6McmKVTS1l5kuhK5ZLh3z6XVFr+QDszjv1Gol0sR94DSvkTy+B1jS03RAzd94HbBFqzT
         Q1tFoxAQZ8WyKlZTQqYaWAhPVUTZNlH1SQnqFqttsi3YpJXcA0vzJ+XeRguzxRpi/7gO
         nSIEHDaoWe/1QqT8nXHTIOnF3u/lUPi0D7CpLiHRbRSQtOo8dz1b+/ngYGyKrLaNK+to
         9ajljCqxU2hEiBHmNAhhRvQ1JpgciEt6By++VNeyHMiRwl7FCzKPd90tiUARDWwkh51+
         a1gg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:message-id:in-reply-to:date:references
         :subject:cc:to:from;
        bh=oJYmRMyoKvrYW7BkIs7EaL719iSioRtTmQy++tq3Ifg=;
        b=XAeHPlzm2tQMU+KbbhGHaa7x6AtCc3rqBvaLEuQOAJHBu9snxUNIuWiCLKAgko10EA
         KSnJ7Kn79CMmnZVF+hsmgRI67njQNNwdRzrFiEOsDiQSzS8BpBFD6xa9tkCifOCoRjtE
         UbzYnbwwQ6hHoscjjPqHTfFTZ3i/gHFP8CyGBCeZjy5oufmlKu0jgWtROFiVeRdtHX6O
         jwH1/epe+tbA17pMrTpqRETIJxchmbMSYooWvUznShTweK1eEopSTqS7v+25VidUiu46
         ICbHSdRo3++TZjX0GcWGwLD/ddBhx0H+qdApYuHhjCQQPJUCMg4PS31ty4gLoBaWvyAO
         DzJw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of whitebox@nefkom.net designates 2001:a60:0:28:0:1:25:1 as permitted sender) smtp.mailfrom=whitebox@nefkom.net
Received: from mail-out.m-online.net (mail-out.m-online.net. [2001:a60:0:28:0:1:25:1])
        by gmr-mx.google.com with ESMTPS id e26si306433edj.1.2021.06.11.09.41.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 11 Jun 2021 09:41:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of whitebox@nefkom.net designates 2001:a60:0:28:0:1:25:1 as permitted sender) client-ip=2001:a60:0:28:0:1:25:1;
Received: from frontend01.mail.m-online.net (unknown [192.168.8.182])
	by mail-out.m-online.net (Postfix) with ESMTP id 4G1mnW3mnLz1s3pb;
	Fri, 11 Jun 2021 18:41:19 +0200 (CEST)
Received: from localhost (dynscan1.mnet-online.de [192.168.6.70])
	by mail.m-online.net (Postfix) with ESMTP id 4G1mnV6lD7z1r0wv;
	Fri, 11 Jun 2021 18:41:18 +0200 (CEST)
X-Virus-Scanned: amavisd-new at mnet-online.de
Received: from mail.mnet-online.de ([192.168.8.182])
	by localhost (dynscan1.mail.m-online.net [192.168.6.70]) (amavisd-new, port 10024)
	with ESMTP id DNOF1t6SXpEc; Fri, 11 Jun 2021 18:41:17 +0200 (CEST)
X-Auth-Info: UjAl/qSEJiAcUzh+KfzDTVzON+wrDx36PXw07BKvqDwzz+F6woY6oRGDBmF8tT9C
Received: from igel.home (ppp-46-244-189-84.dynamic.mnet-online.de [46.244.189.84])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.mnet-online.de (Postfix) with ESMTPSA;
	Fri, 11 Jun 2021 18:41:17 +0200 (CEST)
Received: by igel.home (Postfix, from userid 1000)
	id C31282C3655; Fri, 11 Jun 2021 18:41:16 +0200 (CEST)
From: Andreas Schwab <schwab@linux-m68k.org>
To: Jisheng Zhang <jszhang3@mail.ustc.edu.cn>
Cc: Paul Walmsley <paul.walmsley@sifive.com>,  Palmer Dabbelt
 <palmer@dabbelt.com>,  Albert Ou <aou@eecs.berkeley.edu>,  Andrey Ryabinin
 <ryabinin.a.a@gmail.com>,  Alexander Potapenko <glider@google.com>,
  Andrey Konovalov <andreyknvl@gmail.com>,  Dmitry Vyukov
 <dvyukov@google.com>,  =?utf-8?B?QmrDtnJuIFTDtnBlbA==?= <bjorn@kernel.org>,
  Alexei Starovoitov
 <ast@kernel.org>,  Daniel Borkmann <daniel@iogearbox.net>,  Andrii
 Nakryiko <andrii@kernel.org>,  Martin KaFai Lau <kafai@fb.com>,  Song Liu
 <songliubraving@fb.com>,  Yonghong Song <yhs@fb.com>,  John Fastabend
 <john.fastabend@gmail.com>,  KP Singh <kpsingh@kernel.org>,  Luke Nelson
 <luke.r.nels@gmail.com>,  Xi Wang <xi.wang@gmail.com>,
  linux-riscv@lists.infradead.org,  linux-kernel@vger.kernel.org,
  kasan-dev@googlegroups.com,  netdev@vger.kernel.org,  bpf@vger.kernel.org
Subject: Re: [PATCH 7/9] riscv: bpf: Avoid breaking W^X
References: <20210330022144.150edc6e@xhacker>
	<20210330022521.2a904a8c@xhacker> <87o8ccqypw.fsf@igel.home>
	<20210612002334.6af72545@xhacker>
X-Yow: I will SHAVE and buy JELL-O and bring my MARRIAGE MANUAL!!
Date: Fri, 11 Jun 2021 18:41:16 +0200
In-Reply-To: <20210612002334.6af72545@xhacker> (Jisheng Zhang's message of
	"Sat, 12 Jun 2021 00:23:34 +0800")
Message-ID: <87bl8cqrpv.fsf@igel.home>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/27.2 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: schwab@linux-m68k.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of whitebox@nefkom.net designates 2001:a60:0:28:0:1:25:1
 as permitted sender) smtp.mailfrom=whitebox@nefkom.net
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

On Jun 12 2021, Jisheng Zhang wrote:

> I reproduced an kernel panic with the defconfig on qemu, but I'm not sure whether
> this is the issue you saw, I will check.
>
>     0.161959] futex hash table entries: 512 (order: 3, 32768 bytes, linear)
> [    0.167028] pinctrl core: initialized pinctrl subsystem
> [    0.190727] Unable to handle kernel paging request at virtual address ffffffff81651bd8
> [    0.191361] Oops [#1]
> [    0.191509] Modules linked in:
> [    0.191814] CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.13.0-rc5-default+ #3
> [    0.192179] Hardware name: riscv-virtio,qemu (DT)
> [    0.192492] epc : __memset+0xc4/0xfc
> [    0.192712]  ra : skb_flow_dissector_init+0x22/0x86

Yes, that's the same.

Andreas.

-- 
Andreas Schwab, schwab@linux-m68k.org
GPG Key fingerprint = 7578 EB47 D4E5 4D69 2510  2552 DF73 E780 A9DA AEC1
"And now for something completely different."

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87bl8cqrpv.fsf%40igel.home.
