Return-Path: <kasan-dev+bncBDW2JDUY5AORB6FP5PDQMGQESELZOHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 92432C04068
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Oct 2025 03:35:54 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id ffacd0b85a97d-4270648fc5bsf242179f8f.2
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 18:35:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761269753; cv=pass;
        d=google.com; s=arc-20240605;
        b=U+H4BOVwfGygbngYYwyzU3wM60SGjWk8Si8OoOX0HULakUoHkHFpQpmVhALB2tZ/iP
         FATfEIeZlVVIYsDVgTt08Nsr4fdMP/Jl2bSIwC4WeXaUAg9AhUWWt7OnfIwJUWKWhDhm
         Bpbo1PXLdNcnIKagkmCRyxGJJ9N1onFFtS9Izx62zQLnyf2r05s3g1jHfkNAtNz6O/88
         UXh4xWbdY/JYfSaX65Q/ED0yg6MT2SH0Eg2znE7+EJG+msoUwExwzVTCI1YqESWPriqV
         4YY499U3GSvBEWHUftoLdToZNET3v/mh+QeMdcueqLvtQ17vpZbaU2v2ANQZPaVoXYgW
         Cbdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=S3RDVtIz62Bgj4w1n2e5gUF+P/tbtFarj4jyjfajzT0=;
        fh=Ld8sapWR4TBk6/VNBXVKDVAf83Mw34fc/W0rzRIopOc=;
        b=S5QhIeCedET93mKsCcnrgZD3GFSomdL8yf+dK/qol+vY4+/tbfDzxFxnaHdd2yrDub
         alohOXCSxDJ4527YSD4CvvDoH6kUqkKjGxtCIWSTUlsCayj0l1tTHmhiNmM8DV5bcsA5
         qs1HKHHm70hAw9zfFQ1vB9vQwPSGM7+olmtc91vO+2cWqio3B1NXZf+meIfJ4ddNYp6N
         D3UEz7ogbZ3XhAZRcIbKozhi08BqdU6Kc+NdVzCjGm22RnJUvbEOql2OMu1Mq9ht6/GP
         REfYvtQPndWeQEzUKSha9efgVdjBsnmNOd2Atm6aODbfvs1x0Ld7bNaXPM6R2KbEwNbb
         mCgg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=JTKWCSCw;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761269753; x=1761874553; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=S3RDVtIz62Bgj4w1n2e5gUF+P/tbtFarj4jyjfajzT0=;
        b=BQ2uJZaflnbRXlj7Ne3WZWQt5MPAhdKKRdHOWHimlZuYd1oL/1/1K3VxM7bUyFB/0A
         +tC9RyX/w6Qm+dRKTLTtXQ4TjswG6tFQynnN2cyXQu9K0uuUKVaBF7znrN/v4P96qYew
         0ItXTBY0VGncDP1Gg7vqac0lLTnM1RAenJ80tZkCAz72E04qrG+yooU5+oQwDl7LRc2U
         JjIxlpviME/vqiGpZuq9IyBhFKCvw4ANf4gltZqxCLL5zT0lzN69gz+F71uyUoLyF1/e
         2zYky2itvCVsBz74O4pH0aneIM09qMDLQ5YUB/f057ArkjxbtqvwbCtO12YlSAedlTG7
         rneA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1761269753; x=1761874553; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=S3RDVtIz62Bgj4w1n2e5gUF+P/tbtFarj4jyjfajzT0=;
        b=Ag3H26XWRQEQ64vbOU2XIYOppjLBcWEe5u8Z/iQW/Hzha2pEoAVSdvD+YY2I0wYu+s
         z5o9cK/QNqiyiTg99BeJNta3n0LILFiCm15nWDFObcY3rHXG32Ie6bU+iPfn6kkmZHkR
         VTDpFFcIver8KBZM4yCRSyntVhRgq1U+s9ItZQRumf15+6nXQzk7+P6D6yGJhqxc15dH
         0teIi800VmKNCHRETlgW/2kkE5L9Qwl4r3WNUJmXZJjdmoQ6m4lhgMqF0jdOJLpfjKQ3
         /wLRq2kFWE1krAWspy94pB/etqIIaJZIM+CCEk+kKiK+G6x4qGi2SDhRuf+OJq4DVpeA
         W7Ew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761269753; x=1761874553;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=S3RDVtIz62Bgj4w1n2e5gUF+P/tbtFarj4jyjfajzT0=;
        b=Am2Czc6EBPnQxnpScRr8kVI4/vX9klJpjHp+iteD8h+9KFvPZrOJ5uZ2SxsmBWVehd
         w6qNHs0IcZdXSKSUGGwt3ZFuZubrEIiyfVO/ajjFm8XaP5RAXmvpgdae4gJ4/9B51/nt
         W+qs4cty6hn3nQweJN5uIGp5qL5B516abE948LFQA2dx0FHW865h2mm6T4sSjaEy13Ng
         AFoXyS9dXATdkw1rStMnTwduwX9Ou3er+NPHbxpiLdCGw8NSrcqEboV3WCePOfpDg3J5
         sl5vDaVlx4oUvjEKjeSEL1DDUuVWouclcOVa2PNElROoWyv6ekEOvis1SY6xVP/ccrWb
         YI5A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWQuApHnsvfNBFILV60XxgTuOyQzH43PJ+19jPxXP7ivRkCp8Izfy6d1rY8/75HorGJ1HKMNQ==@lfdr.de
X-Gm-Message-State: AOJu0Yyqekz4GD2/SkTkhAgDY32SbqI2cZ1k2hPccPB/HmOVyULlBSb4
	JJjK0fW6WVq0aI3S+dqT2Ih9EkUNCAn2A80NonnASmWmS6Myeboxixgk
X-Google-Smtp-Source: AGHT+IF1mXV2aaJotnxS3yaWKHp1Etuf9tUNsSJJO6jLYfApo7QJfCyuJ27lAxaG07GcIuST7FE8BQ==
X-Received: by 2002:a05:6000:2404:b0:425:6fb5:2ac8 with SMTP id ffacd0b85a97d-4284e57a373mr4669584f8f.9.1761269752904;
        Thu, 23 Oct 2025 18:35:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bYfmIdNCeow0/cm1IVJlOaB9si1okglxXpH3TyygxgPg=="
Received: by 2002:a5d:5f91:0:b0:3f8:e016:41ab with SMTP id ffacd0b85a97d-42989c9d925ls767671f8f.0.-pod-prod-03-eu;
 Thu, 23 Oct 2025 18:35:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXIO6HRSg9mOmkytLeY+KQAOxa3f7tdtqFVAdJ33HFwdR6yWCilaKsL2ocXoHkcB/gamkpIV62MOP8=@googlegroups.com
X-Received: by 2002:a05:6000:4282:b0:427:4a2:5124 with SMTP id ffacd0b85a97d-429904d7323mr298002f8f.0.1761269750283;
        Thu, 23 Oct 2025 18:35:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761269750; cv=none;
        d=google.com; s=arc-20240605;
        b=iDU8AYS4TEMEOy+j+b1s7cFsxT0uwqQWp31QMxkBb2MRvJVaLP9lXbCcFly0rD+QRR
         W0zdcWu5MM8J+q2SoBNbF1QRXQD109CW9qvKgmXJygWBNzubO5a6ITKeeRWybpFQ1lY7
         7ErX7GyhlFlEWhMvOub6NCZaHQqmOtU8Vr1sjZqHhqtoqPPZogyrTsc0obM9SY1CdR9Q
         Kbd+pDTRXF7duG4xldoFLDcgWFVgLqHiXHRuNjMoiXwczV9sUN1NpjFOYf9OwEDb6Rkr
         LqnAKxzbHTxSEhMsLmR7FOEy23uCSUMcAj4ujN/ucTiCXin6lX/vZnddptIj18a++Nhf
         zHkA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Cq8gqqeYooxgW5KYKmBo5Rs/wh49wN/6rTY6x+8D8QA=;
        fh=TbsJOtiUyWqqLNOaOVC4uD81yZNCQmFF92n2BKWbzmY=;
        b=kVhwYwsKZKu4CKmTFUFj3ePwoJ0xFvV7AGg4QPPE9Rd+58RNCvAeB9CrSj4D6CYlzv
         NUva6e8CGJ/QBEuY+T5qmPlEfU0Ko8htZ4vypueOS75dysJXdd1Rth5lYO0lPAiwZ4JG
         8/qYldZb3I2l/1uOPTaAHIEsVQ6DJ0u+Ep+JME+i+wl+qbiaiEcK+1nmR6soXiOXcfzH
         W7aDJMIYOKagyD9EPDI5oYrOg+R1qKztEopqWR5lAkwdNrWzkl26ZQPnIdkOSma68Vy6
         +ov+5b5xXdPONhPgWOe+9y1xFePZejgK+Q4qLNAWWLGkclFAIyvJ0ivi+DP4yT5N1bWG
         Lecg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=JTKWCSCw;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32f.google.com (mail-wm1-x32f.google.com. [2a00:1450:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-429897e2fc9si75307f8f.1.2025.10.23.18.35.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Oct 2025 18:35:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32f as permitted sender) client-ip=2a00:1450:4864:20::32f;
Received: by mail-wm1-x32f.google.com with SMTP id 5b1f17b1804b1-475ca9237c2so8209025e9.3
        for <kasan-dev@googlegroups.com>; Thu, 23 Oct 2025 18:35:50 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWfSk2wSBR829Fgd+NdcJoTljJrywr8O7NAFu5aJ8jZp3+P6pEhAFxQ6K6FvLTEefKmswQC7aW31/k=@googlegroups.com
X-Gm-Gg: ASbGnctiKb2l3SYzs/EwiO7IWimJhvttDiuAJF41B8xvW50bIPSYH2mJyXuPRZQbizi
	2HhbZUMEqpaCVYkZa0G9qASFdqXVeVlr/NV6byGgeaPWgx6KG2iTIjwQ5dsxcBXvO0/I1Vmcxn5
	E3ssrDpUtYIMMh5E5CqJeElWfUDW77fFEHnOXqnLMdlUeqZfigOV6wA54jTSpozl4XbaanDPaok
	/8lFtmXSQ1dx1W21hUxVtC2ISiHkEU241+lpoaixiFT3K88/8FJYHrp9SlSsy0v1lC03gdPDY93
	waxjl0F3Fvrhcm+wKAA=
X-Received: by 2002:a05:600d:4355:b0:46e:45f7:34f3 with SMTP id
 5b1f17b1804b1-475d39b9552mr1422285e9.8.1761269749552; Thu, 23 Oct 2025
 18:35:49 -0700 (PDT)
MIME-Version: 1.0
References: <20251023131600.1103431-1-harry.yoo@oracle.com>
 <aPrLF0OUK651M4dk@hyeyoo> <CA+fCnZezoWn40BaS3cgmCeLwjT+5AndzcQLc=wH3BjMCu6_YCw@mail.gmail.com>
In-Reply-To: <CA+fCnZezoWn40BaS3cgmCeLwjT+5AndzcQLc=wH3BjMCu6_YCw@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 24 Oct 2025 03:35:38 +0200
X-Gm-Features: AWmQ_blTT_7WNBqDPFmuMJp8o4vQAMauOpamt3NvIm4L5ZNNRzy9gCKm7HE9f0E
Message-ID: <CA+fCnZezciDNL4-Yto8d3bPOc3U07hY1Q_DMk926-1H17Ugx3Q@mail.gmail.com>
Subject: Re: [PATCH] mm/slab: ensure all metadata in slab object are word-aligned
To: Harry Yoo <harry.yoo@oracle.com>
Cc: Vlastimil Babka <vbabka@suse.cz>, David Rientjes <rientjes@google.com>, 
	Alexander Potapenko <glider@google.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Andrew Morton <akpm@linux-foundation.org>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Feng Tang <feng.79.tang@gmail.com>, 
	Christoph Lameter <cl@gentwo.org>, Dmitry Vyukov <dvyukov@google.com>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=JTKWCSCw;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32f
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Fri, Oct 24, 2025 at 3:19=E2=80=AFAM Andrey Konovalov <andreyknvl@gmail.=
com> wrote:
>
> On Fri, Oct 24, 2025 at 2:41=E2=80=AFAM Harry Yoo <harry.yoo@oracle.com> =
wrote:
> >
> > Adding more details on how I discovered this and why I care:
> >
> > I was developing a feature that uses unused bytes in s->size as the
> > slabobj_ext metadata. Unlike other metadata where slab disables KASAN
> > when accessing it, this should be unpoisoned to avoid adding complexity
> > and overhead when accessing it.
>
> Generally, unpoisoining parts of slabs that should not be accessed by
> non-slab code is undesirable - this would prevent KASAN from detecting
> OOB accesses into that memory.
>
> An alternative to unpoisoning or disabling KASAN could be to add
> helper functions annotated with __no_sanitize_address that do the
> required accesses. And make them inlined when KASAN is disabled to
> avoid the performance hit.
>
> On a side note, you might also need to check whether SW_TAGS KASAN and

*HW_TAGS KASAN

SW_TAGS KASAN works with kasan_disable_current().

HW_TAGS KASAN does not and instead relies on the pointer tag being
reset for the access to be unchecked.

On another side note, unpoisoning slabobj_ext memory with either of
the TAGS modes would require it to be aligned to 16 bytes, not just 8.
(But those modes do not embed metadata after each object in a slab, so
your patch seems fine to me.)

> KMSAN would be unhappy with your changes:
>
> - When we do kasan_disable_current() or metadata_access_enable(), we
> also do kasan_reset_tag();
> - In metadata_access_enable(), we disable KMSAN as well.
>
> > This warning is from kasan_unpoison():
> >         if (WARN_ON((unsigned long)addr & KASAN_GRANULE_MASK))
> >                 return;
> >
> > on x86_64, the address passed to kasan_{poison,unpoison}() should be at
> > least aligned with 8 bytes.
> >
> > After manual investigation it turns out when the SLAB_STORE_USER flag i=
s
> > specified, any metadata after the original kmalloc request size is
> > misaligned.
> >
> > Questions:
> > - Could it cause any issues other than the one described above?
> > - Does KASAN even support architectures that have issues with unaligned
> >   accesses?
>
> Unaligned accesses are handled just fine. It's just that the start of
> any unpoisoned/accessible memory region must be aligned to 8 (or 16
> for SW_TAGS) bytes due to how KASAN encodes shadow memory values.
>
> > - How come we haven't seen any issues regarding this so far? :/
>
> As you pointed out, we don't unpoison the memory that stores KASAN
> metadata and instead just disable KASAN error reporting. This is done
> deliberately to allow KASAN catching accesses into that memory that
> happen outside of the slab/KASAN code.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZezciDNL4-Yto8d3bPOc3U07hY1Q_DMk926-1H17Ugx3Q%40mail.gmail.com.
