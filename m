Return-Path: <kasan-dev+bncBDT3ZXW2WUGBBYFB42XQMGQEZJIJ37I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9485787FE81
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 14:19:30 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-41405c9741fsf1014615e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 06:19:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710854370; cv=pass;
        d=google.com; s=arc-20160816;
        b=cZwVNuAAIqvBuv8Zj9wU8HgzznGyV3/Rrr/DurA/ETQtgQ7YxiSk/HojUsLawx89j9
         oRZCh4OE0LWvC50kMVY+IvktxKAmp5RC4hEpBT7oAaF9wClMHqhXXafAV0P4GmLL/rWK
         pUTeAyyhujq9BpFcnUOrU4iimrnzDf+5oEzS0dVI3GIL3n5N4Ipdely3DcIxkshmNEsh
         Jb05W2wgWyjjhpXqoqnBEskpewN5ce3X204r1NBde+fEbWljrN6EgFerlfXSCZx5R0Om
         m7VHcC48TfawSWkQQX7c89HHYIGKJKcOlGpTlQnt6sG9oZMwyXzIf7TC4LFR6l+ruY4/
         Tl1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=zTNaehXRovwR2v3ubeyd3xm/94rto0oFzx6dAr/UaNE=;
        fh=msn7akDOunDWxkTPfUHHtYz6T2Cppl0oTqR66pHcVbA=;
        b=zei+Bj3x4W6hGgxDbZ6SW/N38poVyjmL4gs/SVB7YFoIphChVtlAMYhOIG6X3Sl9Au
         GbGTS3eWa65w15/0mWi4FdhWZALdHrWuQU3msjR5+WCjsizPdyNVEWQ3tH3CkcwuS7Kh
         eSI1SGfgIColwp8+GYO/vFHAIeehaKP2jG+WAmugZsMoK/olE8QaM9CiEEIwSGuuNtb3
         xllS9oQG1f9CRZZDwei0LbqbXf9yXUZ0NElrkJeeJ1gNNApfXd/HXXM1sj6FXRGBSWJt
         +UeaW2NSmUvwjmttgBrtA8zRwLhwpdosAT2GOCZVZkF/2Y6Lzy3CrchWB3pezNkvODZ1
         46jA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@narfation.org header.s=20121 header.b=ebQjNwzQ;
       spf=pass (google.com: domain of sven@narfation.org designates 2a00:17d8:100::8b1 as permitted sender) smtp.mailfrom=sven@narfation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=narfation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710854370; x=1711459170; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zTNaehXRovwR2v3ubeyd3xm/94rto0oFzx6dAr/UaNE=;
        b=aNU/BAQ2nEXDNp+LqHc198ynmNWbyqUiYQYpOYpT8fkh9kWTdjtumkNdRi7YoYjM4E
         qH8NyIOoZvQDrf0SjHevfQRcyeyo1LgJMUzK7jykfeIkT85go5c4fu1Ox5yZYd3GZs9f
         eX9xHpxJju2ceMj+wVQZkgDqxO0jV1lZI1Vjg2/yGmu4f1gwnon9B/b+qV1ScVweT/az
         8V44pvLThRW7U2zLo0HsAsbd621Sh0jomKgXMZ4rNIXofS3p3RXmFkjOK7gAFqpdi1Ze
         Azd2/+vCQxVfaYW2o4NLaDOm3PZB5P0ZTnfYFY0SFxB4T3vfRPv2jfSYHCrjdVyy/DOK
         odJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710854370; x=1711459170;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zTNaehXRovwR2v3ubeyd3xm/94rto0oFzx6dAr/UaNE=;
        b=GvLxUW4mOz7+lrAMDWKl8Nt1rJpHSAdeJyiWt3BooqBPh7PTfaBF1wBtKCQ1Zm7qoI
         xtbvu572uisygSJzEibT/fjKkkF7nNTCWoGSLsM6AX+4NiR1yuHkT+2FqVREXagq2Ll5
         gY/uvTBBLLSjirJozlhaCJfjH6IXmjFqfisiqjaX305RtTGydJ8uUVN47QVy0FpQ3EXA
         rvDC4xnfqdq19NVE8duMoo90p4xkJs1mM+FJwvNVGplJhsjkNBrvlwKAUCte/RLNPnKx
         xGUm2pvQ1KzRzCxzdHXN+KAe0giTW/jRyTRYIOgPRE5NvB/CkMovUenJeZ002Z7NThW2
         o61g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW1rR9NG2NHrUi7/T9UyfEJONpm2DD9EzoKUgqwZYEzzapypq3zZ226YHSl4GwHd3C75tlCsxmz5mCzdMwv8tcnxPVL+b6/Zg==
X-Gm-Message-State: AOJu0Yy6aY5eVpOLfbBwBTj08VbWbQjEw43Wjwv/zFtSixNmU6FQaJxR
	H1ICuhT/0WwXKhgnhZohyPl2SJsFqKgJBpvvZTFR0AOiF3GTFS9e
X-Google-Smtp-Source: AGHT+IHPoZKESmIg/U2MZweo7wPfajsKpB2R7bBUKbv6jWiDhQ8IgKA+HzFn5dVUOT2Yz1sdRTBIlQ==
X-Received: by 2002:a05:600c:45d1:b0:413:f41a:ed1b with SMTP id s17-20020a05600c45d100b00413f41aed1bmr147157wmo.3.1710854369134;
        Tue, 19 Mar 2024 06:19:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8947:0:b0:2d4:77ae:4861 with SMTP id b7-20020a2e8947000000b002d477ae4861ls653817ljk.2.-pod-prod-08-eu;
 Tue, 19 Mar 2024 06:19:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUwMdUnMUVvbk9BxJ/7qO1zycA3/MPJCNeC49fyWE0OV3gOzbW19mxz6ZVI3h4HatWTSaaJeFV+ozI6qCqqMiokF901ZgpfhbNXQw==
X-Received: by 2002:a2e:7d02:0:b0:2d4:2203:f9a6 with SMTP id y2-20020a2e7d02000000b002d42203f9a6mr1930488ljc.15.1710854366186;
        Tue, 19 Mar 2024 06:19:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710854366; cv=none;
        d=google.com; s=arc-20160816;
        b=YFBTBomJk7vgXWgAJPIivgNp76OusdnVpOl/34WAlvf4Alku8xSUGM+yq22SqcmQee
         o8V9kFXZKGn40etQR0mQac11Js3C9EY21S3AF/XGVHf6J97OTwsl9W9BCkhqOGgjPPDn
         l65rasV0v5o89px4CqfVw7jLHPSAK9yXXA+6hCnWjYyDrt5b3PqInyFgNgS5kY2wiI1t
         GvcHbWyEsbjhmFCPZHwP3DeDZ3bRKbC1LqAyWUpF/vdUayq420pPQbN889AqJ0XaACAv
         IJcuAavm4419nN+7wnSaH3h5JX+rg8MovbDI+vjDaEW79UaX9zH6uPvtDynEfsqN1jN+
         LLDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:to:from
         :dkim-signature;
        bh=qlMWgzCdIDDA3TfwtyMcSQvofdYr4JxDgv8/lzTuVSY=;
        fh=YQdbWOxavwMBF8ZwgJV+MBFTKn9ZPUi7Sn0TeLwz4Lg=;
        b=Y5vNvchucl2NlW+mHOOpTUtNU5EhGHOCD8NFejOjWSFYj69F87e41v5jjh8CkjCfIG
         KkhG+unMBe3docAQ0WktjRSeTxoAZvFW5CLLB3CI6TaSqJfVN/ZJOnGxGt0U3na6hQAb
         ThEf2XUopxr9g10U9NgkiZE21NWJZS586cledoXC9ToFVxNj3bf5q20c4X9stJZ1j7yo
         5yhVFlHoU7ApAsVam9HoWv5GsoCwtFaLy5mLwBLdXopTH9j5L8S6x7AenaUfmK86uxbM
         muNbb/ujXY3J7glK+XO+ar8dtzMeyEv9JbKazMPh76wtGTT0KCjwZiwzAulzzOrvIpej
         EThw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@narfation.org header.s=20121 header.b=ebQjNwzQ;
       spf=pass (google.com: domain of sven@narfation.org designates 2a00:17d8:100::8b1 as permitted sender) smtp.mailfrom=sven@narfation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=narfation.org
Received: from dvalin.narfation.org (dvalin.narfation.org. [2a00:17d8:100::8b1])
        by gmr-mx.google.com with ESMTPS id bd22-20020a05651c169600b002d4721d2d8esi580462ljb.2.2024.03.19.06.19.25
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Mar 2024 06:19:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of sven@narfation.org designates 2a00:17d8:100::8b1 as permitted sender) client-ip=2a00:17d8:100::8b1;
From: Sven Eckelmann <sven@narfation.org>
To: akpm@linux-foundation.org, andrii@kernel.org, ast@kernel.org,
 b.a.t.m.a.n@lists.open-mesh.org, bpf@vger.kernel.org, christian@brauner.io,
 daniel@iogearbox.net, dvyukov@google.com, edumazet@google.com,
 elver@google.com, glider@google.com, hdanton@sina.com, jakub@cloudflare.com,
 jannh@google.com, john.fastabend@gmail.com, kasan-dev@googlegroups.com,
 kuba@kernel.org, linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 mareklindner@neomailbox.ch, mark.rutland@arm.com, netdev@vger.kernel.org,
 pabeni@redhat.com, shakeelb@google.com, syzkaller-bugs@googlegroups.com,
 syzbot <syzbot+8983d6d4f7df556be565@syzkaller.appspotmail.com>
Subject: Re: [syzbot] [batman?] [bpf?] possible deadlock in lock_timer_base
Date: Tue, 19 Mar 2024 14:19:20 +0100
Message-ID: <2615678.iZASKD2KPV@ripper>
In-Reply-To: <000000000000901b1c0614010091@google.com>
References: <000000000000901b1c0614010091@google.com>
MIME-Version: 1.0
Content-Type: multipart/signed; boundary="nextPart2316114.PYKUYFuaPT";
 micalg="pgp-sha512"; protocol="application/pgp-signature"
X-Original-Sender: sven@narfation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@narfation.org header.s=20121 header.b=ebQjNwzQ;       spf=pass
 (google.com: domain of sven@narfation.org designates 2a00:17d8:100::8b1 as
 permitted sender) smtp.mailfrom=sven@narfation.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=narfation.org
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

--nextPart2316114.PYKUYFuaPT
Content-Type: text/plain; charset="UTF-8"; protected-headers=v1
From: Sven Eckelmann <sven@narfation.org>
Date: Tue, 19 Mar 2024 14:19:20 +0100
Message-ID: <2615678.iZASKD2KPV@ripper>
In-Reply-To: <000000000000901b1c0614010091@google.com>
References: <000000000000901b1c0614010091@google.com>
MIME-Version: 1.0

On Tuesday, 19 March 2024 11:33:17 CET syzbot wrote:
> syzbot has found a reproducer for the following issue on:
> 
> HEAD commit:    35c3e2791756 Revert "net: Re-use and set mono_delivery_tim..
> git tree:       net
> console output: https://syzkaller.appspot.com/x/log.txt?x=10569181180000
> kernel config:  https://syzkaller.appspot.com/x/.config?x=6fb1be60a193d440
> dashboard link: https://syzkaller.appspot.com/bug?extid=8983d6d4f7df556be565
> compiler:       Debian clang version 15.0.6, GNU ld (GNU Binutils for Debian) 2.40
> syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=13d9fa4e180000
> C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=137afac9180000
> 
> Downloadable assets:
> disk image: https://storage.googleapis.com/syzbot-assets/26b55a26fc12/disk-35c3e279.raw.xz
> vmlinux: https://storage.googleapis.com/syzbot-assets/6f39fa55c828/vmlinux-35c3e279.xz
> kernel image: https://storage.googleapis.com/syzbot-assets/e1e0501539e6/bzImage-35c3e279.xz
> 
> IMPORTANT: if you fix the issue, please add the following tag to the commit:
> Reported-by: syzbot+8983d6d4f7df556be565@syzkaller.appspotmail.com

Sorry, this is a little bit off-topic. But how does sysbot figure out the 
subsystems (like "[batman?]"). Because neither the reproducer nor the 
backtrace nor the console output mention anything batman-adv related.

Kind regards,
	Sven

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2615678.iZASKD2KPV%40ripper.

--nextPart2316114.PYKUYFuaPT
Content-Type: application/pgp-signature; name="signature.asc"
Content-Description: This is a digitally signed message part.
Content-Transfer-Encoding: 7Bit

-----BEGIN PGP SIGNATURE-----

iQIzBAABCgAdFiEEF10rh2Elc9zjMuACXYcKB8Eme0YFAmX5kNgACgkQXYcKB8Em
e0aRihAA0kDB39knEezz051yKh214KQyzCHU9DDVkDQEJKEhl9AMpB/1R4O5poka
SiwAwoSoP5A5kkczS9gtZGmEcCTSCjPx+Zj5aGgGylhgnHsLoA67qxQhiXDu5EWx
QSXqPtTmfNboRsZ8433zCQcUjN4tHc+r/mxFRkaBcRMWQh5tVXpeYjAB5rkOshVP
/Gnp/V9b3rVqu7STsr2npZT3F0SDk6yj2Oi810d0pnNzR2y49DmabnqzWtPe7sX4
d0/zPlX80F7FYrxjbi7LmjNYUoRrudHTXrb8FZaptsa+mIwVQ01UnK7sm/wWW6xF
BVuEC4j3OyaL9HEHgp9o7lxMNMx7KqYwimrewgPqeMWNHOkYX9swwRGzHUkU5wuC
TbbtgbAJaTtBroNZ4AqxwWO8LviRFhwwABtA6zb1VD/WOu8chQ7dgxAEJs3QdEUK
zVXOaOZefHULjIoJzRoPqwcnE67cvYwlmfHZnEVEp9YPXvdcrjswghJ+TeNoBt3s
+rrgbAsvbTxl/N5EF6Ke4OoVg4qDIY2djOubxk+l5r/Od0thLbHWaFq5vYg2G5Zq
VCX52iuKimsHb9Uso3kCzkGjcE2a/UcZu+9pgD4njh1CS+5l7bO89eknX8+yY1Kw
mOLKMD6oyYfDVWWIj7HNhlQxFZdR+mZoiG1FItjoJ7Pof8CRuZk=
=B2hL
-----END PGP SIGNATURE-----

--nextPart2316114.PYKUYFuaPT--



