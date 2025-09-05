Return-Path: <kasan-dev+bncBCCMH5WKTMGRBY645LCQMGQE3VZZFCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 53077B4532E
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Sep 2025 11:33:25 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-72108a28f05sf60856426d6.3
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Sep 2025 02:33:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757064804; cv=pass;
        d=google.com; s=arc-20240605;
        b=N62wEdwDQtOkljZ76jYwTRa6Fqe/lYxRMqkcTzQQrp4ueQ7GBeicZ6oWlUG2Sadd9D
         nHAW7fOyYtwLiCzqCaD+gDwdX8NehFaqFz4R3P390WwmfQigldTSJ+5NWbmOnrRy64gB
         6+dYvJtRZck80LQZ5ReSeTPw7V/XGwRTRdyDJlz9HF5CuQN/dLiLs3fj8TZ9iq5QrQXe
         WRoehKS5zhDqftVqpD5Y/6i068uZvJPaU5NAJNA5jnsgtykJbtiRgSsjo+9Yn+jJCNyS
         dHCXyR/6v1pga9AE8VN5+SYBMz+ANTF38m/+Tg+3k8uzBLcxB9w549VMA3+MuZSZl3Vn
         qw5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=uCyiSQFXG5E6ETCSNm5hSzKiYkLHOtpyvNW79ast9Pg=;
        fh=B31HR9vFqtgY/uB+YjFdASpR8ckp1sjzOl71dYpOvEA=;
        b=Eg6VxC4Km5s5LfPlj4A+w1g1LzL8LlgGf8Qn7IHBV0hzoi6MxERNAo4tz0kHWne3wV
         XV2oYPsP2RcxfhmhGNO6W+M9zCQtgAuRrIP0+tLwARZtfEfj9EuaQL2uIIjU8yJeIpni
         IEjnJ5LQFfH8V7H/+OC/GOQTjiMwYmOT4hBGfMH/9Ny2/prAsQ2Ek74SUPDZBEHXRkNT
         6wrhYYePLVmFq7j6maeODGRp0ewIrqR5VDmFgkYrlDVqr7KE+tCnCH1vn3PNhXyfH89S
         8Ld3UMq/0LC99HXg2YGlZFgChRL/ynLBOlHf6+/CWPqtPhcUqXZRivNRenBvE2wzwj9C
         jRrQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="LcVxP/zj";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f32 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757064804; x=1757669604; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=uCyiSQFXG5E6ETCSNm5hSzKiYkLHOtpyvNW79ast9Pg=;
        b=s9t4a/aXD3f4p9sNe11PMnbsFziLryCMEx9hAg3U9kax3BdRMBtQeOCPbbV+ajAHVL
         bqvg/Tq9gRbgQNyuFQ/MoBOk9gRNkLh4U2A7j4TxG+IgbtImzl3LUfUQ6wzMea3B3oKZ
         BTk1tdvlo2cdcUWEf4fJEkkla5/pjL0w+vCGtlaR/qt75qqpYb1fDe0ihLXgnpUC8HZ5
         ktGWDaeLNVRdYQmyTKqWipH/Skb6JXV5jes/24hM0iqGJgIQ/Bo8H8G9lGPyZZShpWc3
         LY0kfw3FDI5TKyBN4FZmYLLVppT9TekU53NPXN8/qG+3TZOrvY6ZDlW69SEABo0atiI0
         4yBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757064804; x=1757669604;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=uCyiSQFXG5E6ETCSNm5hSzKiYkLHOtpyvNW79ast9Pg=;
        b=PX7H9yoPaz45M2B3fCSvMOiDjkR7gFfj4EZZOiDMw0wPbCljSfZS9APU3uNsnC+FZx
         T7n7jRZMgIYSIRi13kClvr/PQ5e7pKWoqxU+I42/k+WlADD/EBSRE1t2KmUVzT4OUvCk
         bfuSbRMDSzP63gsQEHaDTM3t6R87FLfzuIGAkNiSkU8GaUcFIDwmOI3WW5n+IQzMLNZ4
         QgteYAgmnNJQFsVUXH2VY/uTvMbbmN8/nstOUTRzLh7LmNQxvALl/u15/d4Rc0Ch6e9Z
         0kPlX4+6veaTmfxvU7hjXHjyCFsAC+LgHXdoZEhPvQjCzhfXQDwguX87OXTR7VeCh0YN
         5nBw==
X-Forwarded-Encrypted: i=2; AJvYcCXGmrfedVV5pSI0442G/2TBRcPTRRT1/812ecubLMDnIaVjkYPFmL9K+/QzsBuqGd4QchcrWg==@lfdr.de
X-Gm-Message-State: AOJu0YyeTd9w4WpB8ryOkVBBq9au1Uszjq3kBMbIIKMAJjekTURfVOIn
	AW4LM1kKGDTVwf9npPBcFeSRsDJhzy53yYgz/A1934ce8HPodC7f/Jwx
X-Google-Smtp-Source: AGHT+IFG7jtsx+cUIODcj54GeKw715D22boSEzGO8FTwOld7fzRMh2zH2RHeXpuRcTi/P7iRfEaHMg==
X-Received: by 2002:ad4:5f0e:0:b0:729:6523:71ed with SMTP id 6a1803df08f44-729652372ccmr67090696d6.30.1757064803913;
        Fri, 05 Sep 2025 02:33:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfG5OzkOuuZUq7RorHwT2FezrpSKIs6VRgMWC96SNls4Q==
Received: by 2002:ad4:5f8c:0:b0:70d:ac70:48d7 with SMTP id 6a1803df08f44-72d3ba782b0ls5572686d6.1.-pod-prod-06-us;
 Fri, 05 Sep 2025 02:33:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUN+z7kBbZ1kySfioQxzu90J51IoU0M3TrW9CqzIuL71dNWiRAzxdPnQLHhfYgFvGDqyQN3ot03AE8=@googlegroups.com
X-Received: by 2002:a67:e713:0:b0:519:534a:6c31 with SMTP id ada2fe7eead31-52b1c33ca0bmr7804272137.31.1757064803080;
        Fri, 05 Sep 2025 02:33:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757064803; cv=none;
        d=google.com; s=arc-20240605;
        b=e7SVc3ywubfR0MBXW+zoCtdWnLR7U8GWz7VBJWNHiFXjmxilT29ACSis3SnyMlpvR5
         wl9Cp7dTPNaZ81luiFh1TFxmuQGTsEB0q2XbAg+tNcFsMTaFFzcY1fNRl885thla/Wys
         v0C9r2lndbfTaWIYwoYZm5qyiSaPrzTRRuqdAUK/d+KNdm5xEnz3i/H2zyyUOdgDFb/y
         rFi7ib7CqpCtOIl0d8gqwHfm7ADorflpltN8t9ym09Ufg7u+RNY5lQLngwMYnAarWU3u
         Bi9RYdUxvuurQSZHEOL5zOpB1t5fMHunULCdsSJJo8E1j+7iqGKzU2A/yY1PFOqkOlPE
         dLAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=8dxTlO6r9HaqREYsy2WnogBnYUWROJNvm/8zDKLkYW4=;
        fh=wQaDe3qn2iDSKWSSebDF/BcR9LZcvcbSYFqa0FtkQWs=;
        b=dKIQ7/q5fytEABbNZc8X3kde3ncn3CfVliNSnzpvjmc6nNdXUtaXO3lMoDOZ8N/ZK6
         b6K5TvllGLRbyYmOD80X2KSS98pu3ZvW1fFm4xBqEfzAEojclcXjzscT7oaDPv2TVsh/
         mDPxUfgHVOqpZzWjjwFZBvVwlQcl5KoTupMCqgi4okwK2NQgJXnDrdy5D9l3bXXeoUS/
         oznbW/n2tXtdZJBcLE45rFrXSVhtusqkkgoISnGLKyl7CljtRQA/hfVu3lKh95/8bz32
         1HWBXUpnDUjpmCvetr2DlaOG8Bx6p82c2TibROB9WTtMCByvGcU0KafzdmBlC7rLrV+p
         DMZw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="LcVxP/zj";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f32 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf32.google.com (mail-qv1-xf32.google.com. [2607:f8b0:4864:20::f32])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-52aef469018si706060137.1.2025.09.05.02.33.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Sep 2025 02:33:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f32 as permitted sender) client-ip=2607:f8b0:4864:20::f32;
Received: by mail-qv1-xf32.google.com with SMTP id 6a1803df08f44-7211b09f639so21175816d6.3
        for <kasan-dev@googlegroups.com>; Fri, 05 Sep 2025 02:33:23 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUf0FCfBjAeCW7YZfxmY+GQrJYEjjgcRXAgjmO02zrZYu4ESLqVrvZPXdvu0ByXzKJyioLvLxzO4T4=@googlegroups.com
X-Gm-Gg: ASbGncusaEdAnF87N8t1LK0xbKyO34AF9WfyuDmbDMLvo7evYWUIOEhI51wTbnrCw0l
	900Zi0H7VzdE+A36q93vDjpH/eZ+5zdhdH5MkDt1BSAQMDLmS87GOmS8tYdbUqjGyCR/CymaNH6
	vAfjQV5Wv1cDh2G+3gStwFjqewmRZrz4NY5c3IoVhq5+9ZozCw2C4Bd8dwrvDPcB5o2rrreweET
	+t1tu00CZoDkfvoHBciJIQsOQz9NcjxYB39grNd8Py0p4VfhHzptqw=
X-Received: by 2002:ad4:5ae7:0:b0:71d:9d4c:1907 with SMTP id
 6a1803df08f44-71d9d4c3002mr190638486d6.11.1757064802234; Fri, 05 Sep 2025
 02:33:22 -0700 (PDT)
MIME-Version: 1.0
References: <20250901164212.460229-1-ethan.w.s.graham@gmail.com>
 <20250901164212.460229-2-ethan.w.s.graham@gmail.com> <CAG_fn=UfKBSxgcNp5dB3DDoNAnCpDbYoV8HC4BhS7LbgQSpwQw@mail.gmail.com>
 <CANgxf6wziVLi5F5ZoF2nwGhoCyLhk5YJ_MBtHaCaGtuzFky_Vw@mail.gmail.com>
In-Reply-To: <CANgxf6wziVLi5F5ZoF2nwGhoCyLhk5YJ_MBtHaCaGtuzFky_Vw@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 5 Sep 2025 11:32:45 +0200
X-Gm-Features: Ac12FXwv0qVlytn5UPR2kOevtwfln-V7rGK7j7x55WfwpJGZ-qo_gaxhqOnmQY8
Message-ID: <CAG_fn=VL1j42TxEoWD8Z3jO0uvU0j1JNzPS3BfUXd5AGE-nDkw@mail.gmail.com>
Subject: Re: [PATCH v2 RFC 1/7] mm/kasan: implement kasan_poison_range
To: Ethan Graham <ethan.w.s.graham@gmail.com>
Cc: ethangraham@google.com, andreyknvl@gmail.com, brendan.higgins@linux.dev, 
	davidgow@google.com, dvyukov@google.com, jannh@google.com, elver@google.com, 
	rmoar@google.com, shuah@kernel.org, tarasmadan@google.com, 
	kasan-dev@googlegroups.com, kunit-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, dhowells@redhat.com, 
	lukas@wunner.de, ignat@cloudflare.com, herbert@gondor.apana.org.au, 
	davem@davemloft.net, linux-crypto@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="LcVxP/zj";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f32 as
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

On Fri, Sep 5, 2025 at 10:46=E2=80=AFAM Ethan Graham <ethan.w.s.graham@gmai=
l.com> wrote:
>
> On Fri, Sep 5, 2025 at 10:33=E2=80=AFAM Alexander Potapenko <glider@googl=
e.com> wrote:
> > > + * - The poisoning of the range only extends up to the last full gra=
nule before
> > > + *     the end of the range. Any remaining bytes in a final partial =
granule are
> > > + *     ignored.
> >
> > Maybe we should require that the end of the range is aligned, as we do
> > for e.g. kasan_unpoison()?
> > Are there cases in which we want to call it for non-aligned addresses?
>
> It's possible in the current KFuzzTest input format. For example you have
> an 8 byte struct with a pointer to a 35-byte string. This results in a pa=
yload:
> struct [0: 8), padding [8: 16), string: [16: 51), padding: [51: 59). The
> framework will poison the unaligned region [51, 59).
>
> We could enforce that the size of the payload (including all padding) is
> a multiple of KASAN_GRANULE_SIZE, thus resulting in padding [51, 64)
> at the end of the payload. It makes encoding a bit more complex, but it
> may be a good idea to push that complexity up to the user space encoder.

As discussed offline, it might be good to always require the userspace
to align every region on KASAN_GRANULE_SIZE or ARCH_KMALLOC_MINALIGN
(whichever is greater).
In that case, we won't break any implicit assumptions that the code
under test has about the memory buffers passed to it, and we also
won't need to care about poisoning a range which has both its ends
unaligned.
Because that required alignment will likely depend on the arch/kernel
config, we can expose it via debugfs to make the userspace tools' life
easier.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DVL1j42TxEoWD8Z3jO0uvU0j1JNzPS3BfUXd5AGE-nDkw%40mail.gmail.com.
