Return-Path: <kasan-dev+bncBDP53XW3ZQCBBYOG5LCQMGQEL3VCAAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id C37D0B451F7
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Sep 2025 10:46:26 +0200 (CEST)
Received: by mail-qk1-x73a.google.com with SMTP id af79cd13be357-807802c9c85sf435133585a.3
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Sep 2025 01:46:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757061985; cv=pass;
        d=google.com; s=arc-20240605;
        b=Nj6xFyqU3BsRQBnbzJW0Ou0erL7T0JsIs8tMmb8fXqdLre7f8ynN3CD6sJ9E0fTW2N
         1gEEtB297RTkMoJ3HRbV8+w+pxgVGu4ILO9a1G8Up37CU/Pm/O83jEkMbvp9fQ6X9SFd
         hTGKbYnjOOumHtGw4JjXg/GcD0OeKME0qejmDhHpyJzR7dGKc+/tmJnSBNC8YCGWxWKV
         mDQUF0d52ynxLrijOQsvp2bvNWOaENJfuZ19qscazkndDJLB3gKy5Fq7hNsfoGPQqy1U
         wUSBLbzxAmAZVpXf7Z4LcPqIHdYNIXenU/wN70Lj9Vyw1yldwBkh+kNLfW4/ZELKdko1
         0zuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=ntFMw9vFQyspDelz1k+FBthYIvbLbChRTI5nyYk1Eyc=;
        fh=BaEIUNC5K+Iw+ZVzta7+NMSiljFgI0065sw73XF29DQ=;
        b=IRyhKCDyukJ3snrm2aqu77FAYD31sYpNLUzfj43WoD1XreAwE2iB2FR2I7xgYjVy3I
         I6mJ2WkZuhdQLPt7OHZL3CbQklU0UgDJ+CAOLHOEkTvEV30b7HbRmS1lGYqvA8ea8Beh
         tSeUWNKgfdVdKN2nrR0IfWyjnzwz7cT8tqVkcQajFHj7MiLgblA5JvscDwKIA0ihE8Tb
         KlvaAYTFROnPUYd9BZZggy3As29b+8vta0NXdxWlv9MWUoVkY3EFwoyKLQ1j0FWhK3u6
         nzhYt/OS9UzZJecP4IlIg6+Yv02mudkK+bMz0Ap+158SlpyDneC3q7AKX7YngwJ5gqlH
         4rEQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=eDrkCioI;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2607:f8b0:4864:20::530 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757061985; x=1757666785; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ntFMw9vFQyspDelz1k+FBthYIvbLbChRTI5nyYk1Eyc=;
        b=ENbSVtlV9JTSyJQRfbS/2vFDc+/KQ/obhsANXeGs7QfhheeWId1S0aKMpNHZU2ItEd
         olxd88eTY7gFfmXxzcXnlO1g0jwcNMLLGA9nzWNhclEGAyE/ujRbEHPdd2U0JpFMvan5
         SCsmwnnLKG05XVtlFZmi+pFbH19dQWBWTOlLoTl5U2TnR3V1Azg2YffzvHgy5IsLXrHv
         6VCakec3TyEEIzb98LdGz1fKdikJfuoFPLevXeEHrG65D2Z2L9Wp5GkkekHV8bsSRwrU
         h8nERdqshmPKN6awC8pgpjAtY3uXAz0Vkgo3XCrDCQdT0bA7jLtGZBHyUsfbfEZ2zMBb
         e02A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757061985; x=1757666785; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ntFMw9vFQyspDelz1k+FBthYIvbLbChRTI5nyYk1Eyc=;
        b=DwODKVSNI/2qbdI5SeClZ3i9qnRePOI4aB1ZWiRV7thii1QbqfWLTkjmN5lL/oj78R
         lexUExwtXZIRnZ8jEbtbkgla/z0AQaRjCb7GSLQfsPsVMDOXXGvm9mvi02AnaxGOFF3C
         GBup/tCQdc/aAGIaZ4xbwnbcYeo27t7yy/hAZ35CQpG8a9SRQWON4QU6STjOJJYSDr3m
         UWHFG7BCcXr4agXqeBlABXrLWduCEmzUzCY18WUPWg+CkL+PvkxZQUyB2wBFERQWlb1u
         U0Y+sroBBKI6wFbhr0xDqc/9L2v8y66KcbZGGXgeZi98htrpOM7N6gSGjA8UB9rIaN0N
         jM0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757061985; x=1757666785;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ntFMw9vFQyspDelz1k+FBthYIvbLbChRTI5nyYk1Eyc=;
        b=j0tffcyTbX0rAwTVW+5cBWiOID57KMqmx8Wv237ituWn3QzQdz/IZNlKFE53NIveFv
         92E5ACDzJw4OJnhXDfTyKz04cg2xqa6ZxxkNiCYJp/29dCY0iqw3dW2KPWMHHkNHDit6
         SJO983uRTFZ0AR0a7wZzmfLf3ufp2Jlq1GL4FAdUWsrLOw8Z62W5CqOcd1q4/CVKGkGT
         nyfTEOiZboIQC6BEiQEfBlnO6vguDFc0ro/MrpnWvIqI2tapBVQp076+ZOSDSyTxvh7g
         RWOOq6JtwmJF+ExtMY0jiY0NdI1yQI3KFme7JUNi+cyki3Zdw+w9RTXLycIOEo3iwTYG
         ZbVA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUkzcUDENAoVh1uqNpiJkwjiCPvA9rmajp4GYYAmum0ophtFpQbT8HI3JGbQ0J0IddeVOlYJw==@lfdr.de
X-Gm-Message-State: AOJu0YxAH33dl/i6ijZ186xOwUx/QTq64859nOCs/yM+1lAj4/QSTnXf
	6rz0/kAWoi7G0+gW9CZn9cUB0uzJX+dQ0myWfyMcaR6M9Ox8Jeui9Aj5
X-Google-Smtp-Source: AGHT+IFO74mNl9G8JNWQEauMvDp0hJWwc4CXoYmqrE9lpp0FMOrGKvY8EnX5RtHNjj4DLBRmAhKsGg==
X-Received: by 2002:a05:620a:191d:b0:810:aa1:987e with SMTP id af79cd13be357-8100aa199d0mr345458785a.82.1757061985423;
        Fri, 05 Sep 2025 01:46:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfB/aJO1Wzv/hGRf4g3z90vKXUEcNs6UjKZEi6ktv2pMA==
Received: by 2002:a05:622a:242:b0:4b0:9c1e:fca1 with SMTP id
 d75a77b69052e-4b5ea7f763cls6998871cf.0.-pod-prod-01-us; Fri, 05 Sep 2025
 01:46:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUCmkFDOEhEDrlaPj5LJPuJa2vqeEU2/uNzxeKLvUyfRysgAGNGQjPcYrFsNBvyElrGpIMOj5bQgbk=@googlegroups.com
X-Received: by 2002:a05:622a:481a:b0:4b5:e8d0:27e1 with SMTP id d75a77b69052e-4b5e8d02e06mr23583121cf.44.1757061984546;
        Fri, 05 Sep 2025 01:46:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757061984; cv=none;
        d=google.com; s=arc-20240605;
        b=XQrSSzsKTyVnH49z0wivi44G3qoFi0++k2VCAvMEuRstAVvwi7HakegETV6mgZ9ql1
         eT+++aE07p3xmnldEmuH29ZsqrdlDm5T6EFrNxVqfbZMzIjQxWBXfU+XYaHoo+qMhnpI
         YqfZE01mb7imklrQ6Z+64SnyGoNMzz5L2LU4pfiCXQtAFR7jrC0sIKGMlFqVbJM3UEUn
         lVAny9RbnVzwr7kwegFp5ClBykfS1yS4AvASDxRrnTWAguqleWvD+R9R1u39jr4oRLJa
         2eys+DKKVK+ovouuOUoRVz5oE+deIWtNYJkBjbjeTKQnkQz9hoyjhELk5bnYrAoZjlWD
         C2yw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=w/3us9q7SO3a7mU0skwVqh5PccHM5efYByNeek2KuIo=;
        fh=S1DPMxB2iBZwukCbgVtSUAIAY6orzwioOUD1J1LRpto=;
        b=A2JuSsE4V5Lr68EvqLM00tAI6Ef51P+bLx4yqY+UsVyLNwf0GeSbKzrT8kXmk01gKY
         OeHCOjkMhlCF0z5tUJ+XZ5yFM9nPlMadiNjSP3ocKfbBJU5kCrZnmgnzn5G/+oeUOAUN
         qsj42R0UCEeZJveq38Rr4O/2Nw5RFO8pZ9mmxD7en7ZRATsjvEQFnxHf+5kCD8RfMYpT
         RJP3frbwyYEfovLJQnJa7+r9zxKK/T3geZFNOMrruSGeHULLr9uIuHOhiAKBJDFj6dfz
         z9gO5eox4kguIn0Pmxtm7biTjy3la16YqkmaXYyhpBNkQd9hTtwyUguw0IpEZpSwrHlq
         AviQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=eDrkCioI;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2607:f8b0:4864:20::530 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x530.google.com (mail-pg1-x530.google.com. [2607:f8b0:4864:20::530])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b48f7330b3si580741cf.3.2025.09.05.01.46.24
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Sep 2025 01:46:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2607:f8b0:4864:20::530 as permitted sender) client-ip=2607:f8b0:4864:20::530;
Received: by mail-pg1-x530.google.com with SMTP id 41be03b00d2f7-b49b56a3f27so1131701a12.1;
        Fri, 05 Sep 2025 01:46:24 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVF5VJbNIdKpZ3C6kijvu27Op9Qz7PKwXOx6LxsKIpZYXFOMg2Kat0yeuBPTHUZjwxInCIabFGzhTY=@googlegroups.com, AJvYcCXqhA1Uz2ox4b4u1APaAnLsuQcMu0gsefSTWYi4Kmw6NC0Lietpoo3COsR2irSpuBYy7AQCAC170rc4@googlegroups.com
X-Gm-Gg: ASbGncuDDfhfR0bRxtXnVjmexA8Ju21pUvX+9xwMdv/tPdE0+RICH5yU+qk4NEhda/N
	Jrnw2qqoGXQIKxiBW45sukA6B5qiclBOumAWoepSB3uWiSsWN1Q7GztDFUT7BupduZA5XGPDvgf
	AYWNFd3lTQIqpfPtSeS3F2NrZS+e/RgMei6y5FdGsrrATukhjolvxfCZumKtFPZGzliZKr+EqR+
	fej9V9XzPOLbOzQet60x5RRzEhMnKtMWtGnHQ==
X-Received: by 2002:a17:903:19e5:b0:249:11c3:2db9 with SMTP id
 d9443c01a7336-24944b498a8mr331935075ad.46.1757061983557; Fri, 05 Sep 2025
 01:46:23 -0700 (PDT)
MIME-Version: 1.0
References: <20250901164212.460229-1-ethan.w.s.graham@gmail.com>
 <20250901164212.460229-2-ethan.w.s.graham@gmail.com> <CAG_fn=UfKBSxgcNp5dB3DDoNAnCpDbYoV8HC4BhS7LbgQSpwQw@mail.gmail.com>
In-Reply-To: <CAG_fn=UfKBSxgcNp5dB3DDoNAnCpDbYoV8HC4BhS7LbgQSpwQw@mail.gmail.com>
From: Ethan Graham <ethan.w.s.graham@gmail.com>
Date: Fri, 5 Sep 2025 10:46:11 +0200
X-Gm-Features: Ac12FXzjiY59pui3__MIUUA0N5euXw0YDQBMc9KrPXFvKz93QZm3lShTvhMy6Y4
Message-ID: <CANgxf6wziVLi5F5ZoF2nwGhoCyLhk5YJ_MBtHaCaGtuzFky_Vw@mail.gmail.com>
Subject: Re: [PATCH v2 RFC 1/7] mm/kasan: implement kasan_poison_range
To: Alexander Potapenko <glider@google.com>
Cc: ethangraham@google.com, andreyknvl@gmail.com, brendan.higgins@linux.dev, 
	davidgow@google.com, dvyukov@google.com, jannh@google.com, elver@google.com, 
	rmoar@google.com, shuah@kernel.org, tarasmadan@google.com, 
	kasan-dev@googlegroups.com, kunit-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, dhowells@redhat.com, 
	lukas@wunner.de, ignat@cloudflare.com, herbert@gondor.apana.org.au, 
	davem@davemloft.net, linux-crypto@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=eDrkCioI;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2607:f8b0:4864:20::530 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
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

On Fri, Sep 5, 2025 at 10:33=E2=80=AFAM Alexander Potapenko <glider@google.=
com> wrote:
> > + * - The poisoning of the range only extends up to the last full granu=
le before
> > + *     the end of the range. Any remaining bytes in a final partial gr=
anule are
> > + *     ignored.
>
> Maybe we should require that the end of the range is aligned, as we do
> for e.g. kasan_unpoison()?
> Are there cases in which we want to call it for non-aligned addresses?

It's possible in the current KFuzzTest input format. For example you have
an 8 byte struct with a pointer to a 35-byte string. This results in a payl=
oad:
struct [0: 8), padding [8: 16), string: [16: 51), padding: [51: 59). The
framework will poison the unaligned region [51, 59).

We could enforce that the size of the payload (including all padding) is
a multiple of KASAN_GRANULE_SIZE, thus resulting in padding [51, 64)
at the end of the payload. It makes encoding a bit more complex, but it
may be a good idea to push that complexity up to the user space encoder.

What do you think?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANgxf6wziVLi5F5ZoF2nwGhoCyLhk5YJ_MBtHaCaGtuzFky_Vw%40mail.gmail.com.
