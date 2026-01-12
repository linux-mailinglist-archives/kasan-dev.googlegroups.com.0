Return-Path: <kasan-dev+bncBDP53XW3ZQCBB445SXFQMGQEEC7XUSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb13b.google.com (mail-yx1-xb13b.google.com [IPv6:2607:f8b0:4864:20::b13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7BA62D151C5
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 20:43:49 +0100 (CET)
Received: by mail-yx1-xb13b.google.com with SMTP id 956f58d0204a3-646c87dca90sf1839796d50.3
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 11:43:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768247028; cv=pass;
        d=google.com; s=arc-20240605;
        b=juU2viEWHilnuNxPS8W+wlTEXzSwPUEdESG/PbXI2EM702X0VZwaiXZktBZndDoO4m
         Or8toTjM9W7E+aDUOcJ2CCp3IE/O8ex/kt8iyQp+t3F612XQH6ckOSLRjcbCDaTbjKCF
         F3zpyNr2pbPPo5X7dzckzRkt7JyYmBCXFzpcd4rEAdI9dniTBvUL9AxuyDRzRF7FXaB2
         5u3/QN3UHAkwEWmwYunzW5USUsCNk9OIly8iGMeMGdOuS1gHgjLy7XE/Pviw/DD+hLn3
         0v59pVebX1+wQKX75npVnii2rIqdhEwqLy0nJODzCUAfF+xFzYll2OCd0Mo+4/Ff5Va2
         ksLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=jnCELcevsEEmx66kktyRUe9WBKm4imHC4CDMY1AefXM=;
        fh=+ctWBVD88kWNkENCbEJS/LlxBvPbeLTEE6SfUx2TfXo=;
        b=F2OcCncXsIIX3d6PVZYEyWOmWR21gyizBOZV9/bxI/HJTTxjEFNwH76X5in0VfTFEY
         2NOw7eUWUP6saR5vR1wp7Mqg9I9sQLdl48PRIrsDEsqA3CwmONJJ85NNPt6+zACppVFT
         hrmcycjyTHZ7l6etBunc3ou6wGCkEHQiHGnUcS9t94U6ZNSc2acgwPeV2Ifl2xFbHooN
         +jEq6NZuFyY42MavyEnOP1p8oP6mMfV1munQOaIvf7Y85ku2KVqVdT7m9s+WSoDqoWs/
         4HYC3E9MdxFQtMKk0zjYAkGAfvRRjnp1RIQJd1IYwlRufi8iAUAeWYC64axx+VbeBW33
         jqBQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Kpj4IYHT;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2607:f8b0:4864:20::122b as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768247028; x=1768851828; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=jnCELcevsEEmx66kktyRUe9WBKm4imHC4CDMY1AefXM=;
        b=t1ulYPtQwJV8P0A0AZwTb3QgI9fMTImVNaOxsh6fJc3GS5RYtOZLeoQmMJbI8bDiZc
         gh3/9x2eXzn6WqjDasrBj4I8AoAK3yB61fNIG4smHfsQoac76BcLy9dVK5wCyZrxcW+R
         ykQ7KXAB8paBXXY8FhDxSHGIdPjyiJUa9tEAxwOz0yfOg2KOxHeE4pSydTdXmeYkK4Sa
         giKuAc9whwdlKAY/iHs1fDcvJLCIn8B/FrvRn9Zcg/GEFci1l8z6V0Eo8gVty/wb4da0
         d7tovVab6LkDleSzb1Mu416xINU3PzMX6sE2IeiJH0ZPQYa/BwfPIfY1/ZYEt3R8rMZV
         Dh6g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768247028; x=1768851828; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=jnCELcevsEEmx66kktyRUe9WBKm4imHC4CDMY1AefXM=;
        b=HJgBxbTZC709+DUVHNmYZV5SCe1/eR1vA96/eaCvwP6IksQz0kkohF81zdXgI7GKHf
         u0y9bs1hfhDNL8lFgNGLT8kmRRkaG4+6A5qnNMp8nSut3bwgXzI8a5qlHN2lb1MDahNi
         HENQAFRYQAoeOX0XwQOpfBRz/NmsH7YRA5jj0LPi7xMLR1sSI4H6pnb3KOF+Nmam65r9
         +cDIhNrpM93YsLmSOGVYb1C1+iI4BlbXP1e5CuuRG3D7rE99fhrGTYwoF/pfB4P7Wr1d
         q9PsSNRgpTTW57n35W+kY51/I17UeV5VyTUj7dDzPGXg4He0JUdpbPIFwux6GDkc6peS
         ndkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768247028; x=1768851828;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jnCELcevsEEmx66kktyRUe9WBKm4imHC4CDMY1AefXM=;
        b=NcMFlKXoEjWs5UAcNdGU1ABbde+oANrzFyGqcOGv82yJ8eEWGVxV0BeqSpHOEVbx1q
         b8Cx7hvUviQjBV/rndBQdu+FLXz3mFb8ZL3pNUkPaCOPYaK00L4ww3Jm1BHqOnl+UmhG
         mZTQ7veSPK+hVDwsWEc6yJ4mE3gA7x40ONxWPCwmvNgzfU9LAG3w0Ggs+8VTxcyhDLxI
         6EIDv3b5ZiZMS/wpaWfGA5d1CPTjhMkyAmYlLRMBM6XHzVApBO/FOszsFHmEdjP8y5DF
         UisXQSzAu63x4NLv8yFwBUkHTaHQSo7aqxJGGM8ySUwQ0xHtkxICBMJ6Cx5ZFhcQ2Lab
         1iMw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUUBqJ+1UI8IMhbtklXvwsBC1u7HtP9lHXau3iIVrytwmd5UNI2uzVdksPb5K+aWT3apizIIw==@lfdr.de
X-Gm-Message-State: AOJu0Yy/fG0r9xtNgl9JDWzTGgsSi1ndWAp/WeqUGb/LGzX8WeQV2OVc
	dOh0qk/TIZ6OHevnhK18YmYG3+HE9kOt8xlmpSuKtnlcLQoB9L+vsVdK
X-Google-Smtp-Source: AGHT+IHr5BSle7evRcbWQJv3Qz9c6SfkdJWMsBFIk7CI2EQwDN1p+ekVQNtIBsuLVP12XuyzL8LDVg==
X-Received: by 2002:a05:690e:400a:b0:644:45a9:c0d1 with SMTP id 956f58d0204a3-647169b02c7mr13208821d50.0.1768247027897;
        Mon, 12 Jan 2026 11:43:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FgWwTllX20NyWroxAp0L1TfnMIsn09FB+BPhO7bNuJkw=="
Received: by 2002:a53:ef85:0:b0:644:730d:6219 with SMTP id 956f58d0204a3-6470bd2608els4724940d50.1.-pod-prod-05-us;
 Mon, 12 Jan 2026 11:43:47 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWepwxc+hPQ6rOkFNmRZp/t79d2bp7AZQs+/qL2rW+QvOawG1FhSD6su9iI0LMyxflu+2eA8cvmwc4=@googlegroups.com
X-Received: by 2002:a05:690e:1404:b0:63f:a3d8:1b0e with SMTP id 956f58d0204a3-64716b33a7cmr16005819d50.12.1768247026974;
        Mon, 12 Jan 2026 11:43:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768247026; cv=none;
        d=google.com; s=arc-20240605;
        b=XXzC0eUpnTr7sYjjjzvYQDf/tnQv8A8lzTWsttWmjPjGiut5hyKvNB+NmqrOO3NC1x
         WieqZnGqHd+q93buN1jv7VpsZx7U4piwp0nJE/IhuUPPhlMN920tuDyw5ENbdQhSwk8y
         w+VEQ+QVqsCbVend7x4YX79Ncb2t5EHPXFxcnNa7wbVnUbehy9A3/QAS1gXIQQeXKF00
         xaj809uNBg+WCH2s0Iq44O5U9U9Tivc5KsglpjOqMRRu81OZO+6VDyoao75beyUW7T4i
         L7kFXNrlxtarNdahDWYS09KaUg2y+Y7g1UfIJgKjAo5FzDlE4VKzkojm/iZrq5fr903q
         t88g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=MAxVjP6c4Om6u8vsm6jVY6NUCkgy7e4h2yG64mnXs5A=;
        fh=3fBtr9fffm1FlMmAztmkwNvWBIsyIbD+ulL3IAiiKNY=;
        b=jeH80z+kGHF/CMB1FM5nFEjvcWWgOc+AVF8m+LbOm1huVrChfAU4YDb+TsfZtEZ6rE
         l1Ku8kfhbTC2LPLZKgprfYrNKjWxY48X9m1qbbc4uJfNrNVet4n5mTHEwdIZRvNQHfqK
         LFQhbojz6eq9rIjYv6ehM9NkwzXcwn653a+Q3kkWW5BCNeMSammJtuocdp8VuRoKeCNQ
         dyj6PWj/0p6OJzc4+w+HsqG0/vqiNO8ZZePA06uvsGP19M9MX9XrdE35Nby9TEXCVOEJ
         Ibdd3rGbDHk+NKufT4EUvKDg5SDuNdiA98/gnvzP8uWMx7Kehv8vbntFoErqIi15J2DD
         1wjA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Kpj4IYHT;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2607:f8b0:4864:20::122b as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-dl1-x122b.google.com (mail-dl1-x122b.google.com. [2607:f8b0:4864:20::122b])
        by gmr-mx.google.com with ESMTPS id 956f58d0204a3-6470e082da9si675356d50.6.2026.01.12.11.43.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Jan 2026 11:43:46 -0800 (PST)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2607:f8b0:4864:20::122b as permitted sender) client-ip=2607:f8b0:4864:20::122b;
Received: by mail-dl1-x122b.google.com with SMTP id a92af1059eb24-11f42e97229so10475974c88.0
        for <kasan-dev@googlegroups.com>; Mon, 12 Jan 2026 11:43:46 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXg8PbEEiIUcy4yJrkY64Xp+bt47cQk7u96KqrTo/g8O14VVb2TdD1U+JFQzmlMlMq4AhXP4reLbx4=@googlegroups.com
X-Gm-Gg: AY/fxX5jDI7gIfxTh/0BxHUWUoi7s13u0HbJGM0uz+fmAHJEpJvNkHSFNiMuy5q8UOP
	2tYJM9X8EF1mxnLcGOufzothk9l8EhlJp+qO6hlO990bR7qCGkh2ie7Q6vYnZPTEx+r5fZEE9OL
	UYSnbJonOs1Z05ODRflhcDgdwx7oSzXtLROl1NYz9cQ+MO/E06+velbS6peWFD9SCtCCuKrcfr8
	JjDP4jU9DpOylJuv7ywkj2b4PjlOWvscRYbdlasbn9JJs2cab+/vcFKN5mMtoPEHJM10nDJ
X-Received: by 2002:a05:7022:220d:b0:11b:ca88:c4f9 with SMTP id
 a92af1059eb24-121f8ab9c96mr18145001c88.2.1768247025780; Mon, 12 Jan 2026
 11:43:45 -0800 (PST)
MIME-Version: 1.0
References: <20260112192827.25989-1-ethan.w.s.graham@gmail.com>
In-Reply-To: <20260112192827.25989-1-ethan.w.s.graham@gmail.com>
From: Ethan Graham <ethan.w.s.graham@gmail.com>
Date: Mon, 12 Jan 2026 20:43:34 +0100
X-Gm-Features: AZwV_QjnGtbKh0drXweXXMzt0JXRbTQf5yAyudSCZCAyLdJxE_GC_2wiEvkNplw
Message-ID: <CANgxf6xKrawktF4wPQOs08q5Ob9N_Ff7-=f_hRiZ9yKq4LN0oA@mail.gmail.com>
Subject: Re: [PATCH v4 0/6] KFuzzTest: a new kernel fuzzing framework
To: ethan.w.s.graham@gmail.com, glider@google.com
Cc: akpm@linux-foundation.org, andreyknvl@gmail.com, andy@kernel.org, 
	andy.shevchenko@gmail.com, brauner@kernel.org, brendan.higgins@linux.dev, 
	davem@davemloft.net, davidgow@google.com, dhowells@redhat.com, 
	dvyukov@google.com, ebiggers@kernel.org, elver@google.com, 
	gregkh@linuxfoundation.org, herbert@gondor.apana.org.au, ignat@cloudflare.com, 
	jack@suse.cz, jannh@google.com, johannes@sipsolutions.net, 
	kasan-dev@googlegroups.com, kees@kernel.org, kunit-dev@googlegroups.com, 
	linux-crypto@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, lukas@wunner.de, mcgrof@kernel.org, rmoar@google.com, 
	shuah@kernel.org, sj@kernel.org, skhan@linuxfoundation.org, 
	tarasmadan@google.com, wentaoz5@illinois.edu, raemoar63@gmail.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Kpj4IYHT;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2607:f8b0:4864:20::122b as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On Mon, Jan 12, 2026 at 8:28=E2=80=AFPM Ethan Graham <ethan.w.s.graham@gmai=
l.com> wrote:
>
> This patch series introduces KFuzzTest, a lightweight framework for
> creating in-kernel fuzz targets for internal kernel functions.
>

Adding Rae Moar to the thread (rmoar@google.com bounced).

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANgxf6xKrawktF4wPQOs08q5Ob9N_Ff7-%3Df_hRiZ9yKq4LN0oA%40mail.gmail.com.
