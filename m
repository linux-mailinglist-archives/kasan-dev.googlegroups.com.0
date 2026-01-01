Return-Path: <kasan-dev+bncBCDKVZVOUELBBIE43DFAMGQEF6EVFXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id C2188CECD5D
	for <lists+kasan-dev@lfdr.de>; Thu, 01 Jan 2026 07:03:14 +0100 (CET)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-29f1f69eec6sf141599105ad.1
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Dec 2025 22:03:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767247393; cv=pass;
        d=google.com; s=arc-20240605;
        b=PvRheAtbNJ0njF7+mFvdxpbKnM6GnOc2PQyO4XPYAfPlJUw0pUPv42vpIY/bPXOAuL
         mJGkvBFNH1++y6zF4PLWkB3UXEh2ccLq741u6LxWRhpCoYaVdzMehtX3IkTt2nGpsQLb
         ANAtkOEm1UGCi3LEVjJkWnOW1/ZEZ8+ZoAEPbvzvlnGXBhkTJy7KDBODar+NynuSEzQe
         arOLkEJkc8gXwtr98vpuGwhxWbn7RH/mrpjduiQCI8MALufdpBWpNQX5ycfMHn37daRm
         ZVDrsrtZ9Get1BuMkaQKBbusSs13PALERj5pDdfkutiU26o4CyH1z6u026b0GcT2do2r
         f5Fw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=ys5oGssX/vjv0PJmduU8N4ZkrlPMQFTOVBf7OeG4W24=;
        fh=18m5qpqQfNL4+DnndEC6RL0+5zZmOzyDGBmJQK1A6zs=;
        b=cgKkxw1aK5dY3LnTR0z/fjHQTQrkXT0kkRcaSW55RtRtG9+MYOLOZg0+6Ei+2q2I3/
         UFE+GuomIcw0l/YPsDRIl7h4Td8VRCWlp4FiZR/GBMZGBz3/7oGD+z/iuQha40LbBIAb
         OqKvsetDweqh0NHp8C+ebqFkzL3LLdJmZhyu3v0bw/Oo7o8GczodpWbLkPuND/r1ekkV
         H/znKDPvrZMO5Oblji8k4hE+UkYTQ7hwhBQlnno8EFLvQUAAaYcC7OG7CjPo3ty1nHNV
         Zr2KXZE0F/fdVpEMqpiIPLEeugOjrtlxvI1SMHnEP8uhxrFoMVOKi7wMnShmRF3+nsSL
         PfEA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quora.org header.s=google header.b="X6jAS3/r";
       spf=pass (google.com: domain of daniel@quora.org designates 2607:f8b0:4864:20::102d as permitted sender) smtp.mailfrom=daniel@quora.org;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767247393; x=1767852193; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ys5oGssX/vjv0PJmduU8N4ZkrlPMQFTOVBf7OeG4W24=;
        b=VbjD/YWNbeDM7mw2EFkAuSjhXWbWkRQ8aK+IZEd6rTeq59vShsmXe6HamsaEKGsN/X
         FKuzyXNcAb+iUtWvZc6slkVXeL7ggmV2KgRGF+ft+Ft9VqFUeEhCtkCn5qywsPhrYD4b
         Vd1WI7PKzYDh3OH225h44WX0QG8r+K0OFjajPIwmUh3V/CfMUboKtZdMRQLVii7g+Z41
         9MtPCwKC1xMK8tayO7z98dnyt6uqe0VtkrpKBcUU2l07CDCZ8pj83gO0UGW2jQ7owm5V
         V+6FFRcTB4bEbeO7sYXzImp/PmE1VaPaYD6POJeF3QUvPL+daSgpWgUmFqaz98qfUO+e
         x9Eg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767247393; x=1767852193;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ys5oGssX/vjv0PJmduU8N4ZkrlPMQFTOVBf7OeG4W24=;
        b=E1sRx5RJUgPgA4lqggsv1fd4hMQYg55YJW1wg/HOec1M80KMP4GdmkhZmhFiSkgLTQ
         0+XHJvUhiG8wP190PpLS0iubbgKCAzdOpqQLmrHxeqLp+5+oRMSJNZriqg5AnDbUHywi
         omHowmhDWTuAkbbAXiJcsYTN4CQqEI1t2uQgckU0ErFUnIBNkKD0ITnV+S5QqdLblSQ7
         hO3XbSdmjz4jBxYHkK+x+YKFtX0hq9Fh6vWuKnd6EnpAgcWMLA2kczi3OhIsceTLu4OS
         Im9ylP3+YmQVZI4dI6XKio38b2yneYVXCRrXzWy/Y4vrlPRYXrgGg/hwFJoQFUgZ7Cn7
         TrpQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV3kTj2AA0SiXtkvgQdVinlzO4oE/Fs2X0gWGysZksUwHAAm557bsMHp5juwjMw0dRUKc71eQ==@lfdr.de
X-Gm-Message-State: AOJu0Yzj/A3Dss1SiL3/4EBTyhyxpTEI3XHfp6Dx2o6brFlnvgkenY0K
	FO+BVT5sm6q681o6teDNS5/5yJV0vdp+HdkqXmcccwyFIJOdiPJbYOBf
X-Google-Smtp-Source: AGHT+IH2diVYNSVsf1QeBD1RY5QvqXre81K8TpirpYa7Q6ok8MbYecAkQzKYyA7QQAY7PKXhaRMjZg==
X-Received: by 2002:a17:90b:5547:b0:34c:9cec:dd83 with SMTP id 98e67ed59e1d1-34e921cc010mr34460174a91.27.1767247392775;
        Wed, 31 Dec 2025 22:03:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWaXCsA2lkHxa6vzBtqsik2LvWUFWU9urijTR4vq/KJe6A=="
Received: by 2002:a17:90a:6589:b0:330:4949:15b5 with SMTP id
 98e67ed59e1d1-34f098f6b5els2225350a91.1.-pod-prod-07-us; Wed, 31 Dec 2025
 22:03:11 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXVqHjmGz9rUqt/HjtNsET1QdZ9yiO2k2s44y7hsaxLJGOHUvFBa5LmGFJrqDv8y1UzPhimQKaesNo=@googlegroups.com
X-Received: by 2002:a17:90b:548c:b0:341:124f:474f with SMTP id 98e67ed59e1d1-34e921e8a0fmr26557403a91.32.1767247391317;
        Wed, 31 Dec 2025 22:03:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767247391; cv=none;
        d=google.com; s=arc-20240605;
        b=GPyf1oHcK3kaU8BrPLRXS4yWHoFlvtO6jo71xr9WGsd9OrT+Yk2WXopkIFAcv/O5Ir
         rbNBSJOyu6watRtaQEXuMph0QpIMyzRTJSESAjDLeWrUfsGeYDsKMbmh8bz/0V4rNJIN
         zmbHdhPiGvPO4ag6TH2HGLVp+6A1moFN8Onq/KaEKtW1auLZyywymejFLovSxKpXdALP
         Le4+anu+uWHrWMI0dUeB0tG7RKI92U/LSoqp2J7Uo3DdRU4NeH5jWheLIg0mE8CBw+uh
         kUoiqlUuZzZ9768zwYNwcd0EysDpFSz8O3mkp4ONBMRrw/Ews+wXMwf2h+w18Ae2CTfT
         OFJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=3n4zjBn1TeFMxajGcpKV8firhWdO0dTEBSF+Bk4yMKc=;
        fh=MLsACOTXkDrpXLKaay3uPZMlIyZ23RW6ajUTv0St0fQ=;
        b=gbg0xdwGpdg5cU7wgrJocT+PiC0sWXrOPCo81PDFeatiMO6eYMi9+L3XE0e5mgnwEK
         fMMf1uIV3zPRlJzdB0+aTuH/bEJRhKi+CVq/ZhZkbPkq+xhNWp1yXZt5NJfVcprm0CUY
         bYARJFritpSa98Mx9miZFq6/JZ9s1CtW/jCMEIPcbzBn3MiCF0nKUh1FA4HxjHL6pNb6
         VGVrrnVrDacrACEKp7LtOqmA97WclsEb5nyvnVTqQgTxuT5q96s4NTH44Dh+CVVMtTHe
         MZEdkcxXuz2d1lyRRvFkUsd/IKNhlU+mzC+YjB60XbJlJNICGakdNP+fUGKJLK3vf89J
         S0kw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quora.org header.s=google header.b="X6jAS3/r";
       spf=pass (google.com: domain of daniel@quora.org designates 2607:f8b0:4864:20::102d as permitted sender) smtp.mailfrom=daniel@quora.org;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102d.google.com (mail-pj1-x102d.google.com. [2607:f8b0:4864:20::102d])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-34e76be92c2si484823a91.1.2025.12.31.22.03.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 31 Dec 2025 22:03:11 -0800 (PST)
Received-SPF: pass (google.com: domain of daniel@quora.org designates 2607:f8b0:4864:20::102d as permitted sender) client-ip=2607:f8b0:4864:20::102d;
Received: by mail-pj1-x102d.google.com with SMTP id 98e67ed59e1d1-34c27d14559so8831509a91.2
        for <kasan-dev@googlegroups.com>; Wed, 31 Dec 2025 22:03:11 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWiMX4Q26os8NiUDrbdafKfEA39LY7x0EjHNNzJHUU37yWYLZE5xK8TqWYEkGnLwM8Xdz0Rqxr1VzU=@googlegroups.com
X-Gm-Gg: AY/fxX75RTh5f3Hgcsib9ZSeMHjFJDKv/ff62XKARRTPhrBHDvVnh7f906A5xPveX83
	efeWckKpUrv1VOyM+amJ3lVW3SRWCLhgAz8ZEQ0OKEJDtLBlQX3vUaAgLS9RUM2du/hdhKdha5W
	TfBgqg1S2oRQCxB+u5veiAw4Or9MLiHU4450QQS56LkFCSHWBQuHIKNGwq/MuTxGbNQG5mz1+5y
	eTwPDtaUf7KW7XhMsHPqXzgZBLH2JIqtF8yzC2707vgCjZ7n/Eg7U5Szzp3Hchs4L94N04HW2yi
	VToHm92LtuYGwBZQkc71DMxeYjqff3yVLu9OO1bVeuZLj8HGPJKY+8QkOOITGBMlncmolNBb1xf
	+1rUCjR/b5tQmuZ1O9/rWxWihepAPj+VrK6AwxmxPF7cu4WfuSTTDvRr2ALGfkql5xqhVWhzPLo
	HIaWbpntgUX7a8eAePYbZyIwaXbzbxBZaMCFIN58L3zjCjBcI=
X-Received: by 2002:a17:90b:51c8:b0:340:bb64:c5e with SMTP id
 98e67ed59e1d1-34e9212a206mr33236538a91.14.1767247390713; Wed, 31 Dec 2025
 22:03:10 -0800 (PST)
MIME-Version: 1.0
References: <CAMVG2svM0G-=OZidTONdP6V7AjKiLLLYgwjZZC_fU7_pWa=zXQ@mail.gmail.com>
 <01d84dae-1354-4cd5-97ce-4b64a396316a@suse.com> <642a3e9a-f3f1-4673-8e06-d997b342e96b@suse.com>
 <CAMVG2suYnp-D9EX0dHB5daYOLT++v_kvyY8wV-r6g36T6DZhzg@mail.gmail.com>
 <17bf8f85-9a9c-4d7d-add7-cd92313f73f1@suse.com> <9d21022d-5051-4165-b8fa-f77ec7e820ab@suse.com>
 <CAMVG2subBHEZ4e8vFT7cQM5Ub=WfUmLqAQ4WO1B=Gk2bC3BtdQ@mail.gmail.com>
 <eb8d0d62-f8a3-4198-b230-94f72028ac4e@suse.com> <03cb035e-e34b-4b95-b1df-c8dc6db5a6b0@suse.com>
In-Reply-To: <03cb035e-e34b-4b95-b1df-c8dc6db5a6b0@suse.com>
From: Daniel J Blueman <daniel@quora.org>
Date: Thu, 1 Jan 2026 14:02:59 +0800
X-Gm-Features: AQt7F2pcqwrmBNaCtvu-Tp6iGTovd8mXiNWc6H9351vRIZzSvut2G_lxtlrMnfM
Message-ID: <CAMVG2stGtujhT-ouSjJ6Uth0wxH0qAvcwE5OQTNpHJiFtpS0Jg@mail.gmail.com>
Subject: Re: Soft tag and inline kasan triggering NULL pointer dereference,
 but not for hard tag and outline mode (was Re: [6.19-rc3] xxhash invalid
 access during BTRFS mount)
To: Qu Wenruo <wqu@suse.com>
Cc: David Sterba <dsterba@suse.com>, Chris Mason <clm@fb.com>, 
	Linux BTRFS <linux-btrfs@vger.kernel.org>, linux-crypto@vger.kernel.org, 
	Linux Kernel <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com, 
	ryabinin.a.a@gmail.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: daniel@quora.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quora.org header.s=google header.b="X6jAS3/r";       spf=pass
 (google.com: domain of daniel@quora.org designates 2607:f8b0:4864:20::102d as
 permitted sender) smtp.mailfrom=daniel@quora.org;       dara=pass header.i=@googlegroups.com
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

On Thu, 1 Jan 2026 at 09:15, Qu Wenruo <wqu@suse.com> wrote:
> =E5=9C=A8 2025/12/31 15:39, Qu Wenruo =E5=86=99=E9=81=93:
> > =E5=9C=A8 2025/12/31 15:30, Daniel J Blueman =E5=86=99=E9=81=93:
> >> On Wed, 31 Dec 2025 at 12:55, Qu Wenruo <wqu@suse.com> wrote:
> [...]
> >>> x86_64 + generic + inline:      PASS
> >>> x86_64 + generic + outline:     PASS
> >> [..]
> >>> arm64 + hard tag:               PASS
> >>> arm64 + generic + inline:       PASS
> >>> arm64 + generic + outline:      PASS
> >>
> >> Do you see "KernelAddressSanitizer initialized" with KASAN_GENERIC
> >> and/or KASAN_HW_TAGS?
> >
> > Yes. For my current running one using generic and inline, it shows at
> > boot time:
> >
> > [    0.000000] cma: Reserved 64 MiB at 0x00000000fc000000
> > [    0.000000] crashkernel reserved: 0x00000000dc000000 -
> > 0x00000000fc000000 (512 MB)
> > [    0.000000] KernelAddressSanitizer initialized (generic) <<<
> > [    0.000000] psci: probing for conduit method from ACPI.
> > [    0.000000] psci: PSCIv1.3 detected in firmware.
> >
> >> I didn't see it in either case, suggesting it isn't implemented or
> >> supported on my system.
> >>
> >>> arm64 + soft tag + inline:      KASAN error at boot
> >>> arm64 + soft tag + outline:     KASAN error at boot
> >>
> >> Please retry with CONFIG_BPF unset.
> >
> > I will retry but I believe this (along with your reports about hardware
> > tags/generic not reporting the error) has already proven the problem is
> > inside KASAN itself.
> >
> > Not to mention the checksum verification/calculation is very critical
> > part of btrfs, although in v6.19 there is a change in the crypto
> > interface, I still doubt about whether we have a out-of-boundary access
> > not exposed in such hot path until now.
>
> BTW, I tried to bisect the cause, and indeed got the same KASAN warning
> during some runs just mounting a newly created btrfs, and the csum
> algorithm doesn't seem to matter.
> Both xxhash and sha256 can trigger it randomly.
>
> Unfortunately there is no reliable way to reproduce the kasan warning, I
> have to cancel the bisection.

This suggests the issue only reproduces with particular
struct/page/cacheline alignment or related; good information!

Dan
--=20
Daniel J Blueman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AMVG2stGtujhT-ouSjJ6Uth0wxH0qAvcwE5OQTNpHJiFtpS0Jg%40mail.gmail.com.
