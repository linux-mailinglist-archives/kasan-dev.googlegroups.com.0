Return-Path: <kasan-dev+bncBCCMH5WKTMGRBVO6QKQAMGQEJEN7UVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C76D6A83FE
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Mar 2023 15:14:46 +0100 (CET)
Received: by mail-qk1-x73c.google.com with SMTP id ea22-20020a05620a489600b00742cec04043sf5330459qkb.7
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Mar 2023 06:14:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677766485; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q2utWmYN3UYMJjl4VuOUKGsis+Y+Jty19gh8wHUbSmd5b6Ta25bXHJEkmlqqqPPZNW
         5xMF3Ngr10hyHRbDnIYkwAekO4paY6DbiKo9zsMOLAgh5bTA6LchBAfGl369eaSfQF9e
         qR/wyYQxkIhA5v9lLzoxxzGv2MVr64g1+o/RV+sPBXPUpiGmPbWsk1nQe89VSE5JXbiH
         Qvy2B+kMXlOaCJe0jWdP0WURKpYkvlG9RU9Y/ngn+3BorK12rONbvHEIa094ZVpsy3iQ
         alexLnoP6Stcxo2S/T/HJ9FS47zYp4+O2Oe/Fv9LZdL5Jgf2hhjkNaBWNNeZ03h5ZT/t
         firQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/rhJEAOKlSECuBbk1uJw87s8oEuQ+UbfPwoz7yS+w0A=;
        b=Fl+c3dBg0QyqGsg3ZFccddpGQiGzNsWqxKkQDkZNDuF3vMzHjG7pfATC9EpDBc576V
         zcnkdz/whwP2h/doCaXgo/We935H+aLk4oYD9AUfct4wGTQF9tkulTJu6GpTpdZFKQH/
         rG4K9VPWU02zHFSrofdNzXHkt6s6Vu3y3aNTQSQgIfpldP9dxsTQPQF16BYmKeYc/pT1
         BlbXKssFpJthOvwDJrGKmRDaOCIN2ud+shCka6/K587pwO2TaxqT/+jLOJ1CfkeZRpWV
         KKOKxd9ucBrF2NHuVebr4WyOmiYTnHK7mTb4dva6Kbi84UZ8eweYz2W+aDDU3qshErLQ
         oPhw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=BD98Pver;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d29 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/rhJEAOKlSECuBbk1uJw87s8oEuQ+UbfPwoz7yS+w0A=;
        b=rws5nbIZcgbgm/oHWeFzvwkhsEV98ApvEegMyvspRY6o9vIhyp8WMkUMwf11WvYRC5
         XPNrFfDqEOqFntYKsyq/FCBBWpngZwFc11I3xV1Z8/FCLDfuJW5BFmOStarnAzQmgTnn
         4RGXh7WwsFIpfS7XI8GLbh7u6V+uyYG3/XmM8fRgPT4g5kBb+C3qCR3hzjo4B+9zGwsP
         iPR1TiEU4A5/i5M7FhP46scuSy0AbL6sseTwynzm5aoK4SNikhmBjwr4ikMZFEQb9zc9
         SGQ6b3kHbIpchFzfv2F1yRKiMqBoq6qtgYtkv5KarGMrXMu1q9BjXv6Kt44GR6YCXHy3
         HnYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/rhJEAOKlSECuBbk1uJw87s8oEuQ+UbfPwoz7yS+w0A=;
        b=HaXdJcnVhZ5b9Q5gCnMpz86O0RpiLnLPn2lV3TK/aqAdNzXcN1Orm7XxnpogQPtiSF
         2L99s+9kknrAz53qwV3IL44Rd53UZgHKNZSQvWI21A472vZuSA4Y50cJDkGnGiS3ttnY
         w32pIiGQ9g8TU/YtWG9RoRU6adMXvU8n9Tz6axHeQXFzjc/pIC7LOloam5Zx5VY5cB1j
         rnWgJymOqVt3ryffpEPT7YYdXEbkPWZmzWzZhXlv9vyXKkvn6XcMcBGOx7pyZMgdPySr
         6kfymnj5hluYS3oGTIX41Nh0e9NLrL+A9ab2UUJWF7hP78b2yBesKH9q+dx4lErvWUlH
         Rfsg==
X-Gm-Message-State: AO0yUKUy1e5A6EyXgIsKVTDTM8o9Dw+D6kwvM0qb+CK3Yz4M9lMSWzHI
	BMT+lA7FHwMfkfi1FgiuBXQ=
X-Google-Smtp-Source: AK7set+bmrVoq/zEdak6qCPe8h1jzmeot3+CYveuXIDNF8bYgfVw75mA3MrWSaaVa3g4/02/biAhlQ==
X-Received: by 2002:a05:6214:8f1:b0:56e:f4f0:e71d with SMTP id dr17-20020a05621408f100b0056ef4f0e71dmr2750883qvb.6.1677766485374;
        Thu, 02 Mar 2023 06:14:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:51d9:0:b0:3bc:edc5:2588 with SMTP id d25-20020ac851d9000000b003bcedc52588ls20472549qtn.6.-pod-prod-gmail;
 Thu, 02 Mar 2023 06:14:44 -0800 (PST)
X-Received: by 2002:a05:622a:28c:b0:3ba:1bcb:af01 with SMTP id z12-20020a05622a028c00b003ba1bcbaf01mr18235883qtw.59.1677766484842;
        Thu, 02 Mar 2023 06:14:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677766484; cv=none;
        d=google.com; s=arc-20160816;
        b=rO8z2YbxDlwKkSgC5/mbpMKIldiFLDJY5U6KLR4xw8XyZzsj1sHmN2eF6xcWEejNhO
         20WIbcEqP5593PL95XYN6VS2ITkSG3wnqSXazLQltOs8kugCeGImgdbFOXEbRjUvC+u/
         r8sC7wf+/29mOF9bIqKp9rGIa7O22JXck1XkQgwicSCFaE7ev/xtUwgTRpNomnPLWqbT
         2og+sBnhJp0vSBzRCui/waMHTRIqjxtT3qDOI5xvKfCCUf4TjBOeU4dNvnY/23cRTwkk
         QdMgnDx10eOvSEP08hXtFweNQqd2mCMwGyo13ALUjWDJp86saow5yR5f35gmNhN8r0qa
         35hA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=732b5wP+BowSmRkkbJVoygYQGzzLcyCOL0CaRiRQkbI=;
        b=gigQS6N+mjKJf+MDe9+VznekQtLrQylYdewbxguWVqBg3HB1Zbiiw8V+SQrlVnezf/
         +GRqM4MA8NqB07NCQ5UCXKzHmjiptpN5VbqKwvBcQOTMqzE6KjCFiKeJ6rojCkb0NzzF
         2+Jwek17IZYg+8HMEjxYHQ3AHtpDalJ/TpleO1PPxR9flWok6f6kzP8/aCRGWCnkdgsN
         EbStlAlveJ3e3sfsiN3TBDkFfukM7lpUTGp1nZFoth6i0CM4pzxWSx/vOKeSVKtmKgz8
         ej5YjrKwmtukJQKqpjZio35yMk7I8tFGeyO5fDPyqBrzUG/OaJxXVxUV1AxuBzGQqIZC
         e12g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=BD98Pver;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d29 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd29.google.com (mail-io1-xd29.google.com. [2607:f8b0:4864:20::d29])
        by gmr-mx.google.com with ESMTPS id bj31-20020a05620a191f00b00725bdb9a8acsi810980qkb.5.2023.03.02.06.14.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Mar 2023 06:14:44 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d29 as permitted sender) client-ip=2607:f8b0:4864:20::d29;
Received: by mail-io1-xd29.google.com with SMTP id b5so6806706iow.0
        for <kasan-dev@googlegroups.com>; Thu, 02 Mar 2023 06:14:44 -0800 (PST)
X-Received: by 2002:a5e:c243:0:b0:745:70d7:4962 with SMTP id
 w3-20020a5ec243000000b0074570d74962mr4904464iop.0.1677766484171; Thu, 02 Mar
 2023 06:14:44 -0800 (PST)
MIME-Version: 1.0
References: <20230301143933.2374658-1-glider@google.com> <20230301143933.2374658-4-glider@google.com>
 <CANpmjNO0GBpfRbT1YnNnoupVG7TOcuBbTHzxNyZwdJaH3W7w5g@mail.gmail.com>
In-Reply-To: <CANpmjNO0GBpfRbT1YnNnoupVG7TOcuBbTHzxNyZwdJaH3W7w5g@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 2 Mar 2023 15:14:07 +0100
Message-ID: <CAG_fn=VjYhMrXuAR=tyXeC6-wTYA+EmkHQZf5nGwCCKwpApjUQ@mail.gmail.com>
Subject: Re: [PATCH 4/4] kmsan: add memsetXX tests
To: Marco Elver <elver@google.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, tglx@linutronix.de, 
	mingo@redhat.com, bp@alien8.de, x86@kernel.org, dave.hansen@linux.intel.com, 
	hpa@zytor.com, akpm@linux-foundation.org, dvyukov@google.com, 
	nathan@kernel.org, ndesaulniers@google.com, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=BD98Pver;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d29 as
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

On Thu, Mar 2, 2023 at 12:23=E2=80=AFPM Marco Elver <elver@google.com> wrot=
e:
>
> On Wed, 1 Mar 2023 at 15:39, Alexander Potapenko <glider@google.com> wrot=
e:
> >
> > Add tests ensuring that memset16()/memset32()/memset64() are
> > instrumented by KMSAN and correctly initialize the memory.
> >
> > Signed-off-by: Alexander Potapenko <glider@google.com>
> > ---
> >  mm/kmsan/kmsan_test.c | 22 ++++++++++++++++++++++
> >  1 file changed, 22 insertions(+)
> >
> > diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
> > index cc98a3f4e0899..e450a000441fb 100644
> > --- a/mm/kmsan/kmsan_test.c
> > +++ b/mm/kmsan/kmsan_test.c
> > @@ -503,6 +503,25 @@ static void test_memcpy_aligned_to_unaligned2(stru=
ct kunit *test)
> >         KUNIT_EXPECT_TRUE(test, report_matches(&expect));
> >  }
> >
> > +/* Generate test cases for memset16(), memset32(), memset64(). */
> > +#define DEFINE_TEST_MEMSETXX(size, var_ty)                            =
      \
> > +       static void test_memset##size(struct kunit *test)              =
     \
> > +       {                                                              =
     \
> > +               EXPECTATION_NO_REPORT(expect);                         =
     \
> > +               volatile var_ty uninit;                                =
     \
>
> This could just be 'uint##size##_t' and you can drop 'var_ty'.

Indeed, thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVjYhMrXuAR%3DtyXeC6-wTYA%2BEmkHQZf5nGwCCKwpApjUQ%40mail.=
gmail.com.
