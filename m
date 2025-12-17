Return-Path: <kasan-dev+bncBCCMH5WKTMGRBQ4HRLFAMGQEQ3JPDOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 95FC8CC70C4
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Dec 2025 11:19:49 +0100 (CET)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-4ee25cd2da3sf100463411cf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Dec 2025 02:19:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765966788; cv=pass;
        d=google.com; s=arc-20240605;
        b=fNtY4GL4rwidT+CUXKGj9WtHN8tAd6pk/qys29iUl11ggmNkqCUA7U4GFdNYvn0veT
         2b7E1IfMPdneeEXzo9ooz052OJKRP0P/SDcyiLwdJ/QctYHZTofJGDV+tDsRPEvMvjh0
         PzWJp7SyFPUexUPa2KpTeA29vb40nnCLYli0lqPkbZc6ioHzExc+UyBXrTq7PNO/xuFo
         rGd4W6/zF5l+czsaelhoO25SyLXM4VkPhQ1TR/0pFwVPf1rLOkKoPhtENRxR6B5V1Dfz
         QfTCKLl1B4YgfJwnVFj+vbrlvqLrZhBP6RjnbeHZuu8H7XtoHEq8BJwxyxxe75pnbxs6
         rW8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=063qb00Wqmrv8dzZdkDfwk9rCA2gk2Dmt7Cd7KOfwDk=;
        fh=epWSrWJD8oagRifJ3fZAG1feOZ/a+uyMrZKF7G9Q5no=;
        b=bewBp+1lSS2E9tWZgcZYsRWBIE7LWrIiUwWMap4uveFa1aDLJz/GYdWneWFPaTNhVF
         RsJPLNkB45QPhd4gFwMSk0F+8lWc2mxEfnW4aW5Q5iEy9WBtlTyfDIEK3+PXXuDwzTKz
         EreDR3VbFYi26I2HmQnaRW+TDaNPWEYS0ouDQK4PT/UlemT5dXT2RLG3H1muK/tw/ZY2
         65FKwK2fH8UXTZJJUHNDyOHsiJvyx5PEkMMCjt6bPnN04aFqT4gQR5iboXrFZqbY2BVg
         liFrXDkesu+zUzNzu1fv/FYWzrGfzJstqaA+yUcFuH2xCFt+tQGXV/hNZXJBumI7oiB2
         7byw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Sw+D2pVi;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::830 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765966788; x=1766571588; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=063qb00Wqmrv8dzZdkDfwk9rCA2gk2Dmt7Cd7KOfwDk=;
        b=bRymgjoLunMOXntsE7xKyakc3bU7SKRa3TJKYGsn7EB/GeHK/JHYxdE8HTJyF41JP+
         bs7mpAMjbG1AuRxVpx7ajpzn7iWPzQOgCVVDi+yPgDgxWXNjcKnH8Nmlf2QbO1horyOO
         YnnWJk7D55Uj79cAx+cZT5qDdz/S2y6uufbT8DFfug6XPwtaOVjAAXrIbCOjYL94YII8
         6AocpX+cOL7flUpWa1dRc7WXs/aGU++o6ME5GdIb3jwXI+xEREGJyhvVoOFWhRTcO4FY
         n2RjxMHN66czECzQouU35zhUpcPil5rXMcrexoECO8m+6Y7U6tskN6v6Pv+XIRkVlChK
         +evg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765966788; x=1766571588;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=063qb00Wqmrv8dzZdkDfwk9rCA2gk2Dmt7Cd7KOfwDk=;
        b=Z3lGLZGBj8KrZ5K0TAfzl9UMvpJxw6e/nzqQauq7AWdHWDiFCfi+Y5Wxh8/OuoXfuI
         w4hvl5ysVBD7jOij1pT2IbLM5boMRftfl2T0FlbK02tbtzlHuoZx7PATatnmeZkGSFfU
         jhEWS/WfxMBHPYs4RQ4t13U8vzgJVCe9BQjUgiky8apXVqGKheKDmdou6H603xJ6o6C6
         kOIH14upHMdWG86VQ3ZJK1lFKhezXg4z/yRiJjfRRGEsEwxcvs/46JFYwFlok6qpefDT
         Ol1n0jMU7uUcCSG/bvn4K8a+gTiZwdWHA37Ir9kPVkuO0VhQkvlTdtHJX7ggtxQXKAzj
         eHhg==
X-Forwarded-Encrypted: i=2; AJvYcCWoRJVSEQMgDnGcCXAxeNojRV1713SJ2KzrrJ7p766Mod4e4NZVirtwpH6I02Y9TK3FfvvU4g==@lfdr.de
X-Gm-Message-State: AOJu0YxUW3k9gohHrf0ilT0KwUndg8owrBHh699nWGAqKJTWafQ0A2W2
	KPfg6BIuVPWdc2FFY2ev8x9O5+iT2RaYSplkl2Mq3qyccUp8+cFnj2x2
X-Google-Smtp-Source: AGHT+IHfKjNNIfLjHtCT4mX1P4XAV0NAGyWBhO7X+b1eiKjQwewfQh96sqDVofusc62tS/FZV5oFzQ==
X-Received: by 2002:a05:622a:5e11:b0:4ed:df09:a6a6 with SMTP id d75a77b69052e-4f1d04b1dffmr237349451cf.25.1765966788257;
        Wed, 17 Dec 2025 02:19:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbNXcApAfuUxVMsdLpd7By0npkibdNLY//aNf8DJzXAYw=="
Received: by 2002:a05:622a:1391:b0:4ee:1544:bc7e with SMTP id
 d75a77b69052e-4f1ced6e0cbls139933361cf.1.-pod-prod-07-us; Wed, 17 Dec 2025
 02:19:47 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUvXNp7CEPTilWX9FIuYjjBjvH+wxLDGC5CMhpBmlP+wNALkXxYEhx27dyzAKUTXH0/6x4S8fmkH3M=@googlegroups.com
X-Received: by 2002:a05:622a:4a09:b0:4ef:c5cf:ec0e with SMTP id d75a77b69052e-4f1d05e1649mr255238731cf.55.1765966787421;
        Wed, 17 Dec 2025 02:19:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765966787; cv=none;
        d=google.com; s=arc-20240605;
        b=DIiYbHM7Is1YFhQ+U/i+mP6WiZA0IEd4zhkBsG1NksPKgvzXAHAZyt7FeunPijNUN9
         +h4yZUKIJjFZkdtCmfUwKTfymgvkaDIJnZIyO5sud0TMx5U8GipcZK5mTFuIfF2FlNoP
         VUkBXd4gAcB4iumJljTVXzdFS2Ow2frsW61AggGFAxhrSr8bo0ikKuyo3Fa1udsjjEj/
         qsVooj8quN3onitSOBbJfSfreLDenrcytrk/uBW3+EqH6sFwAEQHh3mR54D0atUelDfM
         avG019i7h8JEX5gmrEKtvvKTcX6F0Fn9HYeKH7bqNhnFu8wVVx5+uBa1kJt3jgy5Pkdx
         kbTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=23gqEg6vrrMOt95UIpPZRnWZYiatBfrUBDzMVbZzD8w=;
        fh=AvZorF82mVB15V6gtO2P34agLcKs3rJzA5Eya0u38lA=;
        b=AuA1fN8ddVxR7Ddnz+munTvTk6sDF88UsaPe6NMCcOLwb8l52LuZo0QCugsiGH1Kwp
         a5wJe57nMAy82Dom9SmbwZ7ZmpMCtnCkN8kfQsFh602Cnt6uLRywUw+xvyMlRMO0fdo3
         JgUTa4iqkJiGFBTXxCrzWjvTbMEzJ3R1eLQb9Fl+0ren6FmXQ05q1z9u6u4uwSnQlc4q
         M02X4WQ+kDF4coB28FtVCBgF9o/FRS8587QJKadjmdc8OPFRWhzCDZHvvEUt0zhCJlNq
         O0VHLyS8jKmPz9Om2SUtb1HbUakBCZ165oCTSpNoU4RN6VBcKNtiujgT02XdfwNGgpJh
         yC/A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Sw+D2pVi;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::830 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x830.google.com (mail-qt1-x830.google.com. [2607:f8b0:4864:20::830])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4f345c35307si2469381cf.3.2025.12.17.02.19.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 Dec 2025 02:19:47 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::830 as permitted sender) client-ip=2607:f8b0:4864:20::830;
Received: by mail-qt1-x830.google.com with SMTP id d75a77b69052e-4ee2014c228so39741241cf.2
        for <kasan-dev@googlegroups.com>; Wed, 17 Dec 2025 02:19:47 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWnPxKxytDH+FZOaVJBQzKXS5msO8e0MiX0shPp/RdYp1H9Z8rsMsCpiCsnmBo48IWPPopUh8Y0ZG0=@googlegroups.com
X-Gm-Gg: AY/fxX6jdVCN2lmv7rHr7TnqE7GL/ZLwQbyhFW2MlLhVO0l3M+VhvhGbjdwyRbrkYnB
	TyNepfMyLJNyE/EFLmPmdBqh7+uH0piPBu18Ke3MZ+urwlzEUPitk/+6vTS1d9MgHSJ++PVGO3m
	HBOPBpCyVPT+t/qkofvVH6M8nke1rEP6QyQmB1ZZTNKfNb60oH0EigwPbBhX707GTRomuok/6Ad
	yJPpmv0x4QWvCZG+5u2MUOmDlmp3ktowTGZTtwbCPrjGxgvpE5dHGu+8PxHDd/IAY0DBxF5Ipne
	d/OEhU90RIVcJouR3CD2ulEU
X-Received: by 2002:a05:622a:5c94:b0:4ed:a6b0:5c26 with SMTP id
 d75a77b69052e-4f1d05e102emr259116031cf.58.1765966786794; Wed, 17 Dec 2025
 02:19:46 -0800 (PST)
MIME-Version: 1.0
References: <20251204141250.21114-1-ethan.w.s.graham@gmail.com>
 <cbc99cb2-4415-4757-8808-67bf7926fed4@linuxfoundation.org> <CABVgOSkbV0idRzeMmsUEtDo=U5Tzqc116mt_=jqW-xsToec_wQ@mail.gmail.com>
In-Reply-To: <CABVgOSkbV0idRzeMmsUEtDo=U5Tzqc116mt_=jqW-xsToec_wQ@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 17 Dec 2025 11:19:10 +0100
X-Gm-Features: AQt7F2rCVoKiHzMLr5gq2Ln7RdeonRMo17AX2R1_t7knfurC9ARwqPf8_xuG9S0
Message-ID: <CAG_fn=WvdKZgmkqa09kwLLH3P_j6GFYzopeD-PZ-Qt0-1KUaGw@mail.gmail.com>
Subject: Re: [PATCH v3 00/10] KFuzzTest: a new kernel fuzzing framework
To: David Gow <davidgow@google.com>
Cc: Shuah Khan <skhan@linuxfoundation.org>, Ethan Graham <ethan.w.s.graham@gmail.com>, 
	andreyknvl@gmail.com, andy@kernel.org, andy.shevchenko@gmail.com, 
	brauner@kernel.org, brendan.higgins@linux.dev, davem@davemloft.net, 
	dhowells@redhat.com, dvyukov@google.com, elver@google.com, 
	herbert@gondor.apana.org.au, ignat@cloudflare.com, jack@suse.cz, 
	jannh@google.com, johannes@sipsolutions.net, kasan-dev@googlegroups.com, 
	kees@kernel.org, kunit-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, lukas@wunner.de, 
	rmoar@google.com, shuah@kernel.org, sj@kernel.org, tarasmadan@google.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Sw+D2pVi;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::830 as
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

On Wed, Dec 17, 2025 at 10:54=E2=80=AFAM David Gow <davidgow@google.com> wr=
ote:
>
> On Sat, 13 Dec 2025 at 08:07, Shuah Khan <skhan@linuxfoundation.org> wrot=
e:
> >
> > On 12/4/25 07:12, Ethan Graham wrote:
> > > This patch series introduces KFuzzTest, a lightweight framework for
> > > creating in-kernel fuzz targets for internal kernel functions.
> > >
> > > The primary motivation for KFuzzTest is to simplify the fuzzing of
> > > low-level, relatively stateless functions (e.g., data parsers, format
> > > converters) that are difficult to exercise effectively from the sysca=
ll
> > > boundary. It is intended for in-situ fuzzing of kernel code without
> > > requiring that it be built as a separate userspace library or that it=
s
> > > dependencies be stubbed out. Using a simple macro-based API, develope=
rs
> > > can add a new fuzz target with minimal boilerplate code.
> > >
> > > The core design consists of three main parts:
> > > 1. The `FUZZ_TEST(name, struct_type)` and `FUZZ_TEST_SIMPLE(name)`
> > >     macros that allow developers to easily define a fuzz test.
> > > 2. A binary input format that allows a userspace fuzzer to serialize
> > >     complex, pointer-rich C structures into a single buffer.
> > > 3. Metadata for test targets, constraints, and annotations, which is
> > >     emitted into dedicated ELF sections to allow for discovery and
> > >     inspection by userspace tools. These are found in
> > >     ".kfuzztest_{targets, constraints, annotations}".
> > >
> > > As of September 2025, syzkaller supports KFuzzTest targets out of the
> > > box, and without requiring any hand-written descriptions - the fuzz
> > > target and its constraints + annotations are the sole source of truth=
.
> > >
> > > To validate the framework's end-to-end effectiveness, we performed an
> > > experiment by manually introducing an off-by-one buffer over-read int=
o
> > > pkcs7_parse_message, like so:
> > >
> > > - ret =3D asn1_ber_decoder(&pkcs7_decoder, ctx, data, datalen);
> > > + ret =3D asn1_ber_decoder(&pkcs7_decoder, ctx, data, datalen + 1);
> > >
> > > A syzkaller instance fuzzing the new test_pkcs7_parse_message target
> > > introduced in patch 7 successfully triggered the bug inside of
> > > asn1_ber_decoder in under 30 seconds from a cold start. Similar
> > > experiments on the other new fuzz targets (patches 8-9) also
> > > successfully identified injected bugs, proving that KFuzzTest is
> > > effective when paired with a coverage-guided fuzzing engine.
> > >
> >
> > As discussed at LPC, the tight tie between one single external user-spa=
ce
> > tool isn't something I am in favor of. The reason being, if the userspa=
ce
> > app disappears all this kernel code stays with no way to trigger.
> >
> > Ethan and I discussed at LPC and I asked Ethan to come up with a generi=
c way
> > to trigger the fuzz code that doesn't solely depend on a single users-s=
pace
> > application.
> >
>
> FWIW, the included kfuzztest-bridge utility works fine as a separate,
> in-tree way of triggering the fuzz code. It's definitely not totally
> standalone, but can be useful with some ad-hoc descriptions and piping
> through /dev/urandom or similar. (Personally, I think it'd be a really
> nice way of distributing reproducers.)
>
> The only thing really missing would be having the kfuzztest-bridge
> interface descriptions available (or, ideally, autogenerated somehow).
> Maybe a simple wrapper to run it in a loop as a super-basic
> (non-guided) fuzzer, if you wanted to be fancy.
>
> -- David

An alternative Ethan and I discussed was implementing only
FUZZ_TEST_SIMPLE for the initial commit.
It wouldn't even need the bridge tool, because the inputs are
unstructured, and triggering them would involve running `head -c N
/dev/urandom > /sys/kernel/debug/kfuzztest/TEST_NAME/input_simple`
This won't let us pass complex data structures from the userspace, but
we can revisit that when there's an actual demand for it.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DWvdKZgmkqa09kwLLH3P_j6GFYzopeD-PZ-Qt0-1KUaGw%40mail.gmail.com.
