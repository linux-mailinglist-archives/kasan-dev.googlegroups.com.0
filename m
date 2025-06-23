Return-Path: <kasan-dev+bncBC32535MUICBBTUX4TBAMGQEKNDMSUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D476AE37E4
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Jun 2025 10:10:06 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-6114de00ef5sf609410eaf.3
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Jun 2025 01:10:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750666190; cv=pass;
        d=google.com; s=arc-20240605;
        b=fBqQ+FVA+Vhe1s9owqvt43VtCMFFIs5kk+oGqsC1fT3LbLerXdXX8uvr9DMh121RYC
         JyLr4Axz3kAzycyQYZeoYkcjjQRabMhN5lkh7YPW0QsXn6U8nqSelCGlE8P1ywOWADpD
         1q4d7QsMiwYCR32KX96OiGdGrYbMX43s+4v56e8qmE4ci76P1Xfnm3tCCDwWAM5671So
         iZAd3fbSdwEkCRqXbUQv1KNSn28RV28y/b+WpGkw0SrXBcVV29M+TzgfOvkN3UHIjpFo
         fR8/WsiDYHtWCKJPKEuU3nK3twvgR09QeZS0lm4Q4j0jdyX1yCdTae6enaeEuI6WcKZU
         LaAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :content-language:in-reply-to:organization:autocrypt:from:references
         :cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=bPQvdG4UXP8023x44D4LvJzjEepu+5prBmhbPiNhdXU=;
        fh=ILnGjYVyKvZRGfmgtEODnTPrK8CMoN5WSrE3EFAk3N8=;
        b=THJZ8hk1mk7bS5TIRMkpZF434Nt3BysqI72Dx5Zcy/6xZEPNzhAQpjdnGofQTegQpL
         4KFY/b7r3F4Rx9u9fzxaZVYUHb4RWTqoKXHhwHXItNS1s6yHVcz3ZNOIgLkua3NiOnYz
         k2U1FhYFbNLO0T+Gce909Iw4Ekusp1P1ngHAF4ZDP7sjhyIAw1X98IrRBQUfcUJxegon
         OUZcfAmD2DUm0IV/QGamA7gukDwnP7+NrxRCp1cCgfqS6eqyyixrd+0PCbVkpVtMeK/H
         7sko8ZwRQ7aq2/b7eSLikTW7CdjnzvhI61gaTRtjEM6jb/GpK5hJ1FAt+5TZXqphoLfE
         BjkA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=h3PKdooL;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750666190; x=1751270990; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=bPQvdG4UXP8023x44D4LvJzjEepu+5prBmhbPiNhdXU=;
        b=dE3XESJGOCevDew6uJXR42SAgGclfPsOYzRUdWaCEFdWODzFmEcNjONMrXuLdcO0jA
         UFQ7vEyv4bpI645//BUfuaFCGJziLYf9krLpzo6eT3PFKkoWL3l8L3BfWMHgkwqTTSga
         0YRGvMgHfK17Zot3eEMR/3OyQInxiHYiNtdFxWCtLVcTfKvBBpm4j5WwnY3zG0otJ/EC
         0Clzqx2wGphEAYNOWM0e7zdbyqYaafzhX1bug61BX1mj254W23Kq1HrS/wgrRLiFuEBT
         15E2xZySCsPCr15pV0j/gRTTxKlOF+FGcCz3QUmbX49wUcx88OiNjwOJfMJ9qqoVKjBy
         fbfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750666190; x=1751270990;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:x-beenthere:x-gm-message-state:from:to:cc:subject
         :date:message-id:reply-to;
        bh=bPQvdG4UXP8023x44D4LvJzjEepu+5prBmhbPiNhdXU=;
        b=fZ8btcQ46+K8UCWDXyFtlgty4gCo9mk9iD3hNlnjMVEwBBVeCI78yqMTxdTNKJq/oJ
         g9pibVjXqJpI00t9ppPdJ+1V+6bJHM7LdKIPiEql4vt2rQJg4fOTZDLQdkZ0CGb2a049
         h6/BUNSo5VELDVcP/hOWKhghyQDFy5dWvfLeszvhawblXZmC1EKRwwClZwiieH6Wu4eE
         KANfMRkIVG6V7R+G+aGh/ioiRWfc7YWrm75HTWFrmKjGdDoUbuXiX8LIr49a52ldiCts
         Wko5N/csVa1GMJNKI+pkmRTyM+s67sH15BgGNVRidoA4zCrkFf1nKD2sXzafDn9QfWXC
         W3JQ==
X-Forwarded-Encrypted: i=2; AJvYcCX8eurgeGI70NB/fk7l7oz6VE5+gN8YuVsub9ihHr2Jth6oWut9KW88gUUMw3BqX/faUN/OKw==@lfdr.de
X-Gm-Message-State: AOJu0YzJMjUMeYwmvm/k3DqPDb5l+Qs3U4ZBw3eXxYt8NBIehTxdAiwE
	dOmeRX4TesLB7r+KUrXa/ezxTlouczzNHdPwpeyMRfyTYYKq8LFgV9Dl
X-Google-Smtp-Source: AGHT+IGU9oRWtATx48fU63NprkfSSDqchPMAznn6+NwQbwmC1jZVup98jhK+Q2+r6VcI/bk8Io0Eig==
X-Received: by 2002:a05:6871:547:b0:2d4:ce45:6993 with SMTP id 586e51a60fabf-2eeee5c758bmr7656746fac.30.1750666190391;
        Mon, 23 Jun 2025 01:09:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdZnsgtLK9MnRtvxH/hui0JmnF5nXo8GWPZK8MPMVLZkw==
Received: by 2002:a05:6870:2c9a:b0:2ef:17ae:f2b0 with SMTP id
 586e51a60fabf-2ef17af0849ls1258353fac.0.-pod-prod-06-us; Mon, 23 Jun 2025
 01:09:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWxReZPh1ESCDPBWBCV+P2NGkjh77YIBTs81ioOld9HqzmTvCOV2CXWUKFfLBI/zdP43caSCVOghSM=@googlegroups.com
X-Received: by 2002:a05:6870:311e:b0:2a3:c5fe:29b9 with SMTP id 586e51a60fabf-2eeee5a53e6mr9129679fac.29.1750666189373;
        Mon, 23 Jun 2025 01:09:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750666189; cv=none;
        d=google.com; s=arc-20240605;
        b=DS7Rbt4ElZwaBeyjNHrXxNzYATNhxYqU30qqit6grK9cv3nQjvDrgHLFRw8f8/efYY
         AMbZ0ihicGhcUbNYg7WsBYe9M9CNBMHLiGaO+1K1+crfj20NKIuFwz8zDOZVq2Usqs8y
         YycF8Inqee/9lHs7H8m8+FMY9H1aQYfJ0AnrJ92RtH3DDk741eami2iR/Gl5QhqH9Fsf
         7UNhCwOatvflexxdBczHRWNAJIaZld02TB8bYLlvE6HXA/alvkVG5HhsCCo2DithhXDM
         gSGpemexJT5noUJb1VxpO9QTQywVAbNg6S3P6uMTR0Guk6+g/QVXaCxrfj6TwlsyImiM
         3CoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=ZoLkNCOIuM5JEq5J9oMA6vdOX/Go0Smb3Cqjl+UXzmI=;
        fh=lMmG/nhRegAOQDuRr/nWXrTXevJik/eO7gd2jzxPkWE=;
        b=Vez3JdNorRt0BAOW69HIS7yI++PQovzpNcpDqsH43Q1Es2+nk/DDLAhV4we/ChwCBr
         LIhKQL2lNc9kEky/sIP/QHFPBzwNlN1wtRdH0q3UACt2dikQlVo6EIUNVoSNp0K37TT/
         Q6Mf4Qcj2S2fGmlpSB8bIvm3USiYFBAt5HJqRA1qBvvmnk4nQvWm8IN5fvQKNX0rvbn5
         NTJpp6XTayesTHCyO7MC8YeidLswBdN0CmIRZj92uzyJB62ubVgKlQzVv9b/FEp+/rmG
         IvirbiWCNPT0PP2f7/UhGrjQp8GQHFc8gedkUkzHaeNGAXErAPyk3qUiUDwVygr6/DgU
         PuUw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=h3PKdooL;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2ee58bfe510si265440fac.0.2025.06.23.01.09.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 23 Jun 2025 01:09:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wr1-f72.google.com (mail-wr1-f72.google.com
 [209.85.221.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-173-EXtX6LaSMnC9RuZYWSQ29g-1; Mon, 23 Jun 2025 04:09:46 -0400
X-MC-Unique: EXtX6LaSMnC9RuZYWSQ29g-1
X-Mimecast-MFC-AGG-ID: EXtX6LaSMnC9RuZYWSQ29g_1750666185
Received: by mail-wr1-f72.google.com with SMTP id ffacd0b85a97d-3a579058758so1607349f8f.1
        for <kasan-dev@googlegroups.com>; Mon, 23 Jun 2025 01:09:46 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXSyP8iGpjzWVRG1pG7/GrXnrVww6ZCJd2tvSimuUXAs6Iz+IMesd+ZP6e/6Ikm/GVbqmBK/dnyMos=@googlegroups.com
X-Gm-Gg: ASbGncvrqTTG5VEEF/F+0nB3kzHQ/ySiOWWz/5lNR2B4wn8tLh9MhLk3y46P9YNxAmO
	yWf+lSr1lj1jqKLe9RX6GXWZZ+aW8/A4Kjo4e4QztPZRJzNKgvRu2MNsTJoX6frgjoF40K3bh/D
	oSWc6uLHZRIGaDxKnlNVoSHCHEi3dIG/UR6pYzpXChgiGBOxs3qEqkJc3vF/pYDd0yXbqCKZY74
	w72cKUOvZBpqpCMovVsEaFLmA9ox3IPtN78cpHXoJllzybmS0BIv9z5BkubZc0DIIb2tW83Y6B1
	U8Ks/3OJaQe7dqdYQznGEY+iIvFd8d4dfP3x3ZqiUcxFBxrza4H+KbRq8RjWANooiRGkc+qfUtx
	7NJSoxMu8B6aLsaqYXEFmg3gRYx/roU6NSUghCS0GayB5TvbGvw==
X-Received: by 2002:a05:6000:4618:b0:3a4:f918:9db9 with SMTP id ffacd0b85a97d-3a6d12d52d0mr8203112f8f.32.1750666185366;
        Mon, 23 Jun 2025 01:09:45 -0700 (PDT)
X-Received: by 2002:a05:6000:4618:b0:3a4:f918:9db9 with SMTP id ffacd0b85a97d-3a6d12d52d0mr8203084f8f.32.1750666184934;
        Mon, 23 Jun 2025 01:09:44 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f4e:fd00:8e13:e3b5:90c8:1159? (p200300d82f4efd008e13e3b590c81159.dip0.t-ipconnect.de. [2003:d8:2f4e:fd00:8e13:e3b5:90c8:1159])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-4536470903asm103919615e9.40.2025.06.23.01.09.43
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Jun 2025 01:09:44 -0700 (PDT)
Message-ID: <aac5662d-b764-426c-a763-79053ecea1a5@redhat.com>
Date: Mon, 23 Jun 2025 10:09:43 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2] mm: unexport globally copy_to_kernel_nofault
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>, andreyknvl@gmail.com
Cc: akpm@linux-foundation.org, arnd@arndb.de, dvyukov@google.com,
 elver@google.com, glider@google.com, hch@infradead.org,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, ryabinin.a.a@gmail.com, vincenzo.frascino@arm.com
References: <CA+fCnZeb4eKAf18U7YQEUvS1GVJdC1+gn3PSAS2b4_hnkf8xaw@mail.gmail.com>
 <20250622141142.79332-1-snovitoll@gmail.com>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 WNyWQQ==
Organization: Red Hat
In-Reply-To: <20250622141142.79332-1-snovitoll@gmail.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: BRgPUQDRx8aGbOZlTdF_W_2jgSFc9KE8OnHKjMvdtlg_1750666185
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=h3PKdooL;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: David Hildenbrand <david@redhat.com>
Reply-To: David Hildenbrand <david@redhat.com>
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

On 22.06.25 16:11, Sabyrzhan Tasbolatov wrote:
> `copy_to_kernel_nofault()` is an internal helper which should not be
> visible to loadable modules =E2=80=93 exporting it would give exploit cod=
e a
> cheap oracle to probe kernel addresses.  Instead, keep the helper
> un-exported and compile the kunit case that exercises it only when
> `mm/kasan/kasan_test.o` is linked into vmlinux.
>=20
> Fixes: ca79a00bb9a8 ("kasan: migrate copy_user_test to kunit")
> Suggested-by: Christoph Hellwig <hch@infradead.org>
> Suggested-by: Marco Elver <elver@google.com>
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
> Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
> ---

Acked-by: David Hildenbrand <david@redhat.com>

--=20
Cheers,

David / dhildenb

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
ac5662d-b764-426c-a763-79053ecea1a5%40redhat.com.
