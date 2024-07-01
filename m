Return-Path: <kasan-dev+bncBDW2JDUY5AORB6UNRO2AMGQEKPRAM5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id D19AF91E370
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Jul 2024 17:10:51 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-2ec507c1b59sf38535401fa.3
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Jul 2024 08:10:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719846651; cv=pass;
        d=google.com; s=arc-20160816;
        b=G1g0pQ0KXVvP9DGhn5cxf0ro1+icIc9VCTpE+fEvkMxWZnSKADBgI7oQ7DFfNhVA+c
         NfjoaSkVrRkCYqP2DoupSCQqYq4e+GR9oUTeuz4wSEXeASFK61e4eD8Cp1Lz85RwH6Ho
         xgfoXq3xWUz+OaXUGRd79DQWpIZeF+0uCpXemSbK4VWrh+Owb8AqpOksQruwSyNYKXf9
         qT9TQm4bwPueA+ee+VkhRBTtFLIvWQnU8wiJdIcpHfxXiJhw156RHXcuSxyCxqLAhFxx
         Z5MgTNpmxla0eGFl4oSUiENEw2XAITtkzely9od9FZupWmmP12q4hipbX7uWQkFo9xRO
         OTdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=Jtx62UJt/nwXGa1erH5EWUQbt/iQeKukh5dv3DZsqW0=;
        fh=+9wJYyCBr9AGPqyDJ/D/2hkDyi/sRm31F6Y/q3/K3So=;
        b=lB6WDSbFexwbm52mSMvwvmvySILgsf2Hz45csVTrIc0/COsmf7SFK2JrzSvQqkNQuj
         S0hT25kVrvst5dA2IYM+L1XXAaXg/vFlTJiYUeg25IjmBV4QsGhRsSkC9LG7twXqXMXj
         WbUQLWEbaGG07DpmWaJkkB4b633FtP4kGPxL+LDKwYxR7wkoVwwm6bmyFq1dxtdHlt0/
         ZFP3hl219yl5zfYmucfE9JPI8Of0QGeR7LTCiv3faSHdfYpR7vyKniGSnlxo7f3i4Dh6
         Qnw0/1g4wUUGr19ph9r7NWihTNWCjJKvUVLev3mgfK9D5cSN3s0pM31qETmXoEKOc8py
         hVBg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=cJMncSCZ;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719846651; x=1720451451; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Jtx62UJt/nwXGa1erH5EWUQbt/iQeKukh5dv3DZsqW0=;
        b=jNRNiiDccGjhHtuNg80uAebjw6DxfEdMvSt4LKrn/1INqHkXKES9Y/UEdCCNyIeDv9
         w54KThvZJN3W/TVUni1l3wALG4rU8h0tnBfTBsEB5EdhgbySLYZ79E2MgODrWgHgxoeG
         SaNlDk0SO228bjP3chSa5967GvEzu46D+JmGgvZcXMRPLIP6zP0ScYyIsky7hQJxrP24
         1X5glo0MHhPek4gkQs5o1dBCK68vKdxYncFItvnBemuoUXzd9zxt1+VIcQmfaaFm+xg2
         H1kLw5utTw+/U4S1D+FyOyhKSx5VM/VD+M6qzJetCyqURvpl77Q5CVHBWjc/32paJmAx
         nwIg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1719846651; x=1720451451; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Jtx62UJt/nwXGa1erH5EWUQbt/iQeKukh5dv3DZsqW0=;
        b=ZaA462lh1P/CXp6qakmKdOL7J7sUcwRgkDkTCFsCRG6Hgd84Z2yz9bXpAEMUH28Wmz
         vwmLIrowu0fGwAMDALyBGmQRv8rpwVnYyLqt/iIxbAgaGyiYsiIEOkVSkJhYy/MtJt2w
         UgXLrTAF6q5lVam4LaYDr5bcmZRC9gKPu7q+B7Ma3wMRh/V0nzA4U7VM52m3xc/jk0ET
         CXt5oU10g40DAdfQrvkMzNJi9VOV7nnH8ktL//HPvG5GokEtXYYT2AdYH+I+XSPfd/Ds
         Qk/0+iclAP8YGar9SjS6m+EHyejJ76b+wvPSBWtqHCqhWP4mk7qSDmuppHqBopKqUBIJ
         UYBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719846651; x=1720451451;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Jtx62UJt/nwXGa1erH5EWUQbt/iQeKukh5dv3DZsqW0=;
        b=it0EX5R/hTdLkeaH4VhgURRA286DuZcvvf+H3QeWyUabfuftgrCS4wj9VXvV6T/lDE
         iyi+tKFfmu4rWsunUQZfuMe+2+KjXODUbQjJ63kXEj4x98cFPyYCeiJuUyLBmzA8p5oq
         bvCY8DAm2OKZDQFyr7ruYZkUOuYPVsg5uoYdf85twKNJLW0kvyu+C3HBn4ShD0owjkaW
         805zVY9PR5DX6A2KgLk9GaLM0Lrw3L2cdIPy6loz7ScglhupeYBp1q5H5bIQvEfEBB3+
         SOkxHxs2DfghabfF4J0EX9TEKON206hnnWPj8ElyI3ojdDjLiZ4U6MvRUjDZiFt9kFT4
         SywQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUeqrgo1IfbQWKifP23OsrJNUthiKrgI/NtcZaygI6xpKiJgS0FrRcvnHbgHyIYijpi0+Z2KGqok5xjPOec3l6U7jrcL+0EeA==
X-Gm-Message-State: AOJu0YwFOL/PmtWuCQuY3ewP/VP73zTUqnRL3qS0GIlh7kyzZvmsJj1Z
	Ju4nSTpUbNSykxOmYrspXcW8xMd64Ask/ivupjCX1yCW/1CtsJPR
X-Google-Smtp-Source: AGHT+IFJ/KX4ErMwURT8LbCGsPW1li2+n7e9nfI46nycXo4DiHKMVqwHxCWvulavtvZG8BDp9Kcjhw==
X-Received: by 2002:a2e:b385:0:b0:2ec:57c7:c735 with SMTP id 38308e7fff4ca-2ee5e6f6175mr50501971fa.35.1719846650361;
        Mon, 01 Jul 2024 08:10:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b5da:0:b0:2ec:4f80:327a with SMTP id 38308e7fff4ca-2ee51b28ca2ls14506801fa.0.-pod-prod-05-eu;
 Mon, 01 Jul 2024 08:10:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV56cNC/0FeS7CJDl5YVq0NbmQxbhtOvfD5BxWvOj1GoElylw5ty9zNgvdSl0F1u+J7wQhhBIj/0WGTyehz7pr+AsLIrj8cqtW9pA==
X-Received: by 2002:a05:651c:2c8:b0:2ec:596c:b637 with SMTP id 38308e7fff4ca-2ee5e707c9amr40530211fa.49.1719846648304;
        Mon, 01 Jul 2024 08:10:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719846648; cv=none;
        d=google.com; s=arc-20160816;
        b=RIIianLen0pbuPEvo9g7W3g5qs9l49Mi9StNdS9bhV4KQ6RhXa0CWI7RGoA8DbWvwd
         BWnQ81Jl2Noe/X3uWnlVF6ljcR9WXwTO8BTroRzWoz3A8sCHvVySOb3UhU8cp8wkm/ma
         WpAdKw5M7C1hnWrbAE0DrWF5Vv3604W9/0ifqci90GXj+5v9Tw36fePUG6D51g8cjFY4
         Cw9A/w2/xs1WiiM7NUX6wzJVVkpkbabTtyjiTPp24H2+e4YHNbIpmLD+Ua9kWNGxX3rL
         oxWDoYnwepYOJhVLrSGpgJqtjkCTWRX5kGFdYoNbDObinEeStaRbbUpM0EPIcDzMo0rv
         sfGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=+uoqJDE8Nxw1jtvx0c3KsBxMhbzIR8G4P8HBgB5+rOM=;
        fh=RKCSa2zSEVoxwXe5X9nLM26yccDJP0yLJWcQTC9zOR8=;
        b=LJWtEx9zlfExjMo9mW2MCSkNzowD6Td3Tu8RcA9eKgWZr8L9wLg1T1kRzuq90sKsBO
         Tpg40SrpezRLreHx/sNfywoMFPM5I60CY/nHrAw7WExVG+1PgBdV6AWQ9AHJowf92Zin
         VW2WCnky8d76kgjFQrAaxjXH0yF0UZHl14zNkS2EjYzflRBlJ+o6TuQVdgB3ekDFUwR2
         +itVtsrehIPQB7R4lHm50rIQunhDQZwcazfT5CoQq9Bbe9wcyOJ8P5Mz/OTmQY8V5jDo
         teX7pdPyvJzMBCAtOI0yxp5bNOneNxXj0Dft/LvGIHeZlXMsxAUw6Z1GjWJf3fAA6xwd
         pFIQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=cJMncSCZ;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x432.google.com (mail-wr1-x432.google.com. [2a00:1450:4864:20::432])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42577a0e821si2923685e9.0.2024.07.01.08.10.48
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 Jul 2024 08:10:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::432 as permitted sender) client-ip=2a00:1450:4864:20::432;
Received: by mail-wr1-x432.google.com with SMTP id ffacd0b85a97d-362bc731810so2528210f8f.1;
        Mon, 01 Jul 2024 08:10:48 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXXKtiGAd0vV+HfzFFg+mDySBmQJOq7ODXg3dILv8fyvfOcN7muG2hd5A3rYK3vNn7ddo9Ph4ZnJP3erHgn/+jqxRPK4BB63ZP1DsR45MgaESZutIpSAf/4zUFKxFuw8bTNgfQn/F5QZLIh4w==
X-Received: by 2002:a5d:598a:0:b0:367:434f:cab8 with SMTP id
 ffacd0b85a97d-36775724938mr6201368f8f.43.1719846647160; Mon, 01 Jul 2024
 08:10:47 -0700 (PDT)
MIME-Version: 1.0
References: <000000000000a8c856061ae85e20@google.com> <82cf2f25-fd3b-40a2-8d2b-a6385a585601@I-love.SAKURA.ne.jp>
 <daad75ac-9fd5-439a-b04b-235152bea222@I-love.SAKURA.ne.jp>
In-Reply-To: <daad75ac-9fd5-439a-b04b-235152bea222@I-love.SAKURA.ne.jp>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 1 Jul 2024 17:10:36 +0200
Message-ID: <CA+fCnZdg=o3bA-kBM4UKEftiGfBffWXbqSapje8w25aKUk_4Nw@mail.gmail.com>
Subject: Re: [syzbot] [kernel?] KASAN: stack-out-of-bounds Read in __show_regs (2)
To: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Cc: syzbot <syzbot+e9be5674af5e3a0b9ecc@syzkaller.appspotmail.com>, 
	linux-kernel@vger.kernel.org, syzkaller-bugs@googlegroups.com, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-mm <linux-mm@kvack.org>, bp@alien8.de, 
	dave.hansen@linux.intel.com, hpa@zytor.com, mingo@redhat.com, 
	tglx@linutronix.de, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=cJMncSCZ;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::432
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

On Mon, Jul 1, 2024 at 2:43=E2=80=AFPM Tetsuo Handa
<penguin-kernel@i-love.sakura.ne.jp> wrote:
>
> Hello, KASAN people.
>
> I suspect that KASAN's metadata for kernel stack memory got out of sync f=
or
> unknown reason, for the stack trace of PID=3D7558 was successfully printe=
d for
> two times before KASAN complains upon trying to print for the the third t=
ime.
> Would you decode what is this KASAN message saying?
>
> Quoting from https://syzkaller.appspot.com/text?tag=3DCrashLog&x=3D119fd0=
81980000 :

[...]

> [  229.319713][    C0] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> [  229.327779][    C0] BUG: KASAN: stack-out-of-bounds in __show_regs+0x1=
72/0x610
> [  229.335174][    C0] Read of size 8 at addr ffffc90003c4f798 by task kw=
orker/u8:5/234

[...]

> [  230.044183][    C0] Memory state around the buggy address:
> [  230.049816][    C0]  ffffc90003c4f680: f2 f2 f2 f2 00 00 00 00 00 f3 f=
3 f3 f3 f3 f3 f3
> [  230.057889][    C0]  ffffc90003c4f700: 00 00 00 00 00 00 00 00 00 00 0=
0 00 f1 f1 f1 f1
> [  230.065961][    C0] >ffffc90003c4f780: 00 f2 f2 f2 00 f3 f3 f3 00 00 0=
0 00 00 00 00 00
> [  230.074059][    C0]                             ^
> [  230.078915][    C0]  ffffc90003c4f800: 00 00 00 00 00 00 00 00 f1 f1 f=
1 f1 00 f2 f2 f2
> [  230.086983][    C0]  ffffc90003c4f880: 00 f3 f3 f3 00 00 00 00 00 00 0=
0 00 00 00 00 00
> [  230.095056][    C0] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D

I checked some of the other syzbot reports for this bug, and this
memory state part in some of them looks different.

Specifically, for
https://syzkaller.appspot.com/text?tag=3DCrashLog&x=3D14293f0e980000:

[ 1558.929174][    C1] Memory state around the buggy address:
[ 1558.934796][    C1]  ffffc9000b8bf400: 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00
[ 1558.942852][    C1]  ffffc9000b8bf480: 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00
[ 1558.950897][    C1] >ffffc9000b8bf500: 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00
[ 1558.958943][    C1]                                      ^
[ 1558.964569][    C1]  ffffc9000b8bf580: 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00
[ 1558.972613][    C1]  ffffc9000b8bf600: 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00

This is weird, because if the metadata is 00, then the memory should
be accessible and there should be no KASAN report.

Which makes me believe you have some kind of a race in your patch (or
there's a race in the kernel that your patch somehow exposes). At
least between the moment KASAN detected the issue and the moment the
reporting procedure got to printing the memory state, the memory state
changed. As this is stack memory that comes from a vmalloc allocation,
I suspect the task whose stack had been at that location died, and
something else got mapped there.

This is my best guess, I hope it's helpful.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZdg%3Do3bA-kBM4UKEftiGfBffWXbqSapje8w25aKUk_4Nw%40mail.gm=
ail.com.
