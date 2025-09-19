Return-Path: <kasan-dev+bncBCCMH5WKTMGRBXXDWXDAMGQEK4UVYHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id EB38AB8A2F8
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 17:08:17 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-78efb3e2738sf33021486d6.3
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 08:08:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758294497; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZVeYEe/3fk/OGisrK6Oq6mvjdaEzc7jXnvk39jOPPRfhgoSGiCeqOD5gYlkxOHj8MM
         +ygjw4Pgn4YFG4Jx3pXg8r2x/10Yeoi2aorFR0PwhGYsbQiGbu7DvsUPMMQ1qZYwIaWH
         wkIabXCnZ9XLyBL4ycV8I/BFotoEqX9XoLHVLJ61VRhjYZwEBYi74DY2HAWGyyfA8EsD
         UGd/aXs5S373/1jdpmliqhotvBClLOaVy8j/r94+JnOxemOs9XBQmnEKzhI3Fgvdrg72
         ZeCOdeh4wpxM2aoyw5KpYDxdW/vgYOEm6q0Vs+3ZK1jJM986aaB8XAUBUZRcLC0udvD+
         7UlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jKXWFTsGvh/61HsvKgiZWVyS09Z1o2Mn69HNVjbUPjY=;
        fh=qbeyOtKedJ6ho4tzi48FOpsmZbQnk9VPcxo3oMaPuIw=;
        b=Hlds9Udc/bmVjR/B1IPoC/ObsPGm1WsCGCU8iGm9vaAH0wCj6n97mVTRvVtbsTPg4j
         Ozwn/kCviamM55/LBhpDcBpTwAmzO6CMhq8TefcGQV9vO2tF4z889pnQRyqfzKGbQ+/8
         1oHEzc2K00J7/j47SOXQ8BRf3MvK3G43yKKlri8wauWnAn+RjOs/8Xh0wAncbfzo6QF1
         gtGzFGqUehz5sMZVrk6WDYGEW5+8LBE6Tn6sB3LfaQMi3jbAemWMtQtI6z3p7fF4ZhDB
         jstNc6VLtJCC8HO7ymXEuC8v3QjD5XHdWbtwuihbWV3eBFypwmxCfuDZmXtA0B2Hl3V7
         Czuw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=gz0awRrX;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758294497; x=1758899297; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=jKXWFTsGvh/61HsvKgiZWVyS09Z1o2Mn69HNVjbUPjY=;
        b=Uch8RuVjgt93MaUl0+7yJ5JtqYcTrwGPVWR5iNXrGG1fDtZrqrTUPJHHhcY6zjnoSH
         H9k1ScmnmpK5jabcFH090aWI96J/LXA1rYpP15E28QY5s1r0lX8lz4vqMEtU0i3GIr/p
         7sEWPc+bU/TQ37UDXFyj8i8Iljh9V13NEyrmo8RbIB9qB5gxZx6Nx5sjse1Z6lwpjw+t
         m4hqw8BBWVRV7pnWTsvBPLEsCTAmwGAzjzk+q8FVGGX9OovfLi3+nruNeXv/Do1T0bR0
         JcxJY2EifuDiPnQS8nyaliCuiIUHx5iNl0bRuRBKFV+D7KN0u3S4mYH1kponLHn2SQVN
         Pdxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758294497; x=1758899297;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=jKXWFTsGvh/61HsvKgiZWVyS09Z1o2Mn69HNVjbUPjY=;
        b=vefywdMJK7zErxz2gY6fv3mzpM1DR39Ah5JcCwTVxqtZnVGnUCqtS/IIZTlgTlQYup
         +oc9vxXQBBCtPDu8qKdY1L147XTdON4VjIWwRPUJa7bvipS0OSwClt/tV/B6NWuL+5gs
         aO37Q6/lqYC4I9iaL97SZ82C8AKhJWUZMEVzpbVdvNWeSkQzdls2JGPKdFzNX64gyQgp
         foLv6gjRExsLYHaCQ0MbvDrLhfd3ch3yuW/TwiFGW4ph9DoKEMZeLFPN6HrttiM2uY8t
         rWL2FF0n0tlVs7mlWznjO86wR++w5FsBL7MX8zeqc5GZNgmAfUla+G11cLU+dSiW/rOZ
         /bAA==
X-Forwarded-Encrypted: i=2; AJvYcCXMw8XlxUEq/MqiGK4lS6h003+HKWGtg2EIgjt/uL899BNMbNNLP6LaGH9ue4H0g2H40Qyqqg==@lfdr.de
X-Gm-Message-State: AOJu0YzsVelSqTtEk7U2KlDagjAsk3bARCN9ZfLTsu2iHfxbEGIIIBa1
	HscqYBeR0F4/BPOJSvEnSrpcs3tPViMt4TT+gqbWYoyguhKodcfhl1LB
X-Google-Smtp-Source: AGHT+IEZ8eDjqtzyc6neaz1HR0CIulSTKAKg1mlG2igYin2PU+pbKdHOQy2LpmclB90zB1LGQPA1dA==
X-Received: by 2002:a05:6214:1251:b0:794:309a:870e with SMTP id 6a1803df08f44-79913ac45f3mr43442456d6.27.1758294495182;
        Fri, 19 Sep 2025 08:08:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5MiDaIhk1/YrkVd0ezc7y+OuuGEtqRftLA6kpTu6WMlQ==
Received: by 2002:a05:6214:2626:b0:70d:b7b1:9efb with SMTP id
 6a1803df08f44-7934bac1f06ls30207776d6.1.-pod-prod-07-us; Fri, 19 Sep 2025
 08:08:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWAc77kNTWMcw8inr2Z1KvBq7XsNg99muW9riliDRZuNBg2MySg0QzdPb8OI9k6YHJ9mOH37Cc3bkk=@googlegroups.com
X-Received: by 2002:a05:6214:1251:b0:794:309a:870e with SMTP id 6a1803df08f44-79913ac45f3mr43441586d6.27.1758294494280;
        Fri, 19 Sep 2025 08:08:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758294494; cv=none;
        d=google.com; s=arc-20240605;
        b=gkCz1hiVSB6/LyUNvQvSkONZ6riOoKUzZvwj5FUWh94Xs8vS0el5AcEheEPEfppRoZ
         m6l8YpqQHuJG8n8UWGQwAyE6K47ZQ4jfBcd2SbaU7ZwxK9ewrsxvgGADX0iOQ+fCZpc2
         ntCh6oHJh2fNjfpsOyHUK0aope2Jpcr2bG/Yr/czAePSE9iyhkfte2JAr43M/IgCryNm
         RxxQOj+X0c9Uz4eZ4nNK4kDT0LwgxUGYAmQZx04+M8VIFYIvn741TykZS1pKqMZqXDW4
         7E7CmXVIOpZNUPKzyqQ7r1oYJjINWU7OQsDuWE7lvz+c226LriqySl+HWf0JRQFZPpif
         n1hQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=LFmZTAQu6xp1H90eoajASSZ3CmnWB3SEwm5mOewzT+c=;
        fh=FdhxGXldDGuCAigm5PixGcXp7cO8tmhG/ZikRLcO158=;
        b=Sk6aHtFOLQodFOC0zJDA+F7Ft0NZ23KqzXhqMOcIbS0GZRazfxpooQSRGqM3aW39Sy
         ze8qwP2PPTypKZ33SKCAPldgv6LKdUU/j5tGH/uUQiPnTy77xOFXTCv4Wb6ZRCJPt0gT
         P/QG8D7EEUOo2v7LBgQXgTD62PMSkNlZZRttgBC8uGotcB8SOumHrpiDhI13BrSbmu64
         XAMEtOZq77fzIvgdbK5k7IvDRtqEfVeZGxrC40uCYdH8IgWOcUwgdNkCoZQFnOVoFmZY
         cpngtZohbtRKb3zMWofibh9Vwve2lm/qgoqqMP4JNgCV2Y1npjS9YC/FxqsUZ7eeo388
         y+Vg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=gz0awRrX;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2b.google.com (mail-qv1-xf2b.google.com. [2607:f8b0:4864:20::f2b])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-7934d1c380fsi2237116d6.5.2025.09.19.08.08.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Sep 2025 08:08:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) client-ip=2607:f8b0:4864:20::f2b;
Received: by mail-qv1-xf2b.google.com with SMTP id 6a1803df08f44-70ba7aa131fso22569006d6.2
        for <kasan-dev@googlegroups.com>; Fri, 19 Sep 2025 08:08:14 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUQ7fWt7oddLWUDlFJlkcLSrGHfJ4nZvXiZOlz44wx0J9VVa3KXquM5nd9fcAj7eH02X7fyBJuwAlk=@googlegroups.com
X-Gm-Gg: ASbGncswGh+mEL61pNwXO9A/ZCiPwqc6dtTg1GNZqhZxnxAEdEmlFwkjX7z/LrX+jqD
	x54N9C07E1lKdciSai7jW8lsxLJ1cs5yFQxq07LqT4mdjRYW8SVydeZ5f9617ivSalatzSAtJHP
	2tB7O8szRt54gdjWS5CU7VEc79YTOMMnBep8xh063G6EGKCr6j7jka3pctCm0VSbEsl+yuOa32D
	GcYS5+ogt06s5kyNWvb0YT37Wd0XLyduxF3Hg==
X-Received: by 2002:ad4:5d66:0:b0:710:e1bc:ae42 with SMTP id
 6a1803df08f44-79910e91071mr49973476d6.10.1758294493230; Fri, 19 Sep 2025
 08:08:13 -0700 (PDT)
MIME-Version: 1.0
References: <20250919145750.3448393-1-ethan.w.s.graham@gmail.com> <20250919145750.3448393-10-ethan.w.s.graham@gmail.com>
In-Reply-To: <20250919145750.3448393-10-ethan.w.s.graham@gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 19 Sep 2025 17:07:36 +0200
X-Gm-Features: AS18NWA8NT9J6yW558WFqJ9v7KlWvLUFu5ioEKltNkloZ03huDtjBzwZEdnYYKc
Message-ID: <CAG_fn=VVWKR0JLCTZ8HvB51UX3EYrFg1s_xD-ohOKDQwDHOxHQ@mail.gmail.com>
Subject: Re: [PATCH v2 09/10] fs/binfmt_script: add KFuzzTest target for load_script
To: Ethan Graham <ethan.w.s.graham@gmail.com>
Cc: ethangraham@google.com, andreyknvl@gmail.com, andy@kernel.org, 
	brauner@kernel.org, brendan.higgins@linux.dev, davem@davemloft.net, 
	davidgow@google.com, dhowells@redhat.com, dvyukov@google.com, 
	elver@google.com, herbert@gondor.apana.org.au, ignat@cloudflare.com, 
	jack@suse.cz, jannh@google.com, johannes@sipsolutions.net, 
	kasan-dev@googlegroups.com, kees@kernel.org, kunit-dev@googlegroups.com, 
	linux-crypto@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, lukas@wunner.de, rmoar@google.com, shuah@kernel.org, 
	sj@kernel.org, tarasmadan@google.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=gz0awRrX;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Fri, Sep 19, 2025 at 4:58=E2=80=AFPM Ethan Graham <ethan.w.s.graham@gmai=
l.com> wrote:
>
> From: Ethan Graham <ethangraham@google.com>
>
> Add a KFuzzTest target for the load_script function to serve as a
> real-world example of the framework's usage.
>
> The load_script function is responsible for parsing the shebang line
> (`#!`) of script files. This makes it an excellent candidate for
> KFuzzTest, as it involves parsing user-controlled data within the
> binary loading path, which is not directly exposed as a system call.
>
> The provided fuzz target in fs/tests/binfmt_script_kfuzz.c illustrates
> how to fuzz a function that requires more involved setup - here, we only
> let the fuzzer generate input for the `buf` field of struct linux_bprm,
> and manually set the other fields with sensible values inside of the
> FUZZ_TEST body.
>
> To demonstrate the effectiveness of the fuzz target, a buffer overflow
> bug was injected in the load_script function like so:
>
> - buf_end =3D bprm->buf + sizeof(bprm->buf) - 1;
> + buf_end =3D bprm->buf + sizeof(bprm->buf) + 1;
>
> Which was caught in around 40 seconds by syzkaller simultaneously
> fuzzing four other targets, a realistic use case where targets are
> continuously fuzzed. It also requires that the fuzzer be smart enough to
> generate an input starting with `#!`.
>
> While this bug is shallow, the fact that the bug is caught quickly and
> with minimal additional code can potentially be a source of confidence
> when modifying existing implementations or writing new functions.
>
> Signed-off-by: Ethan Graham <ethangraham@google.com>
Acked-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DVVWKR0JLCTZ8HvB51UX3EYrFg1s_xD-ohOKDQwDHOxHQ%40mail.gmail.com.
