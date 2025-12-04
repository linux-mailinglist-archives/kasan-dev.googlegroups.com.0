Return-Path: <kasan-dev+bncBAABB44LY3EQMGQEQN3SAHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9BEB3CA3B15
	for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 14:00:52 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-37cc3fc4f2csf3994251fa.0
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 05:00:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764853237; cv=pass;
        d=google.com; s=arc-20240605;
        b=O83ER7UqyMwbC/tAiPYyZQmPqKWWYwqwWv2P0/Jw+YxOjV7aLhhgqFLaJUV258IJp7
         c3Ps6ZcpRunt+sC6anCup6gNi6+wkx4LIcwVCS617YVm5FvcAf1vBKL/edJIFsX+Us6z
         5HqaOnhrNQfEgINBtfpTm8XDTG9UY5yjAgKJcFtGTbOkS/amk7wYn4z14D4rN71dWslr
         9CHLnq20WKlOzl7IK1d3SGy02YBENplqsw8ErttmqyVjKscXmKoZwPOY9hXc5ADoXf8Z
         E62qoAfMtcP3vY1+Zi5jpq5PWsGM4S1iwY/91v4I0EvqxOpuQzVIOO0esR5VUVdr/Tf2
         YWxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:cc:to
         :subject:tls-required:message-id:from:content-transfer-encoding:date
         :mime-version:sender:dkim-signature;
        bh=2GQpleJNfjxdaUZ+2kToUvRbg7iGfiLwnlBal/pQUlw=;
        fh=A13D2lNdcr3jPGJ3fziKGwjfhXqkPeGnHY9CiMbE6hM=;
        b=KkJiGO2toOBzrry/+8YuQmeYzSywMNRXD6owGa5in59QTnkMGcCjV4YrjvbSdCRe1C
         vYH5u/Yo09Nf0xHJAEBRfxlINp2r2zqBHVUAW0f46EhsmTZul41tMcm97RXPHhWYtDua
         0+vJB2Dd8ee23ZMm592SXddmaJOtW44yElJbwmnuN3cky9k6iXVlFDeaHGC0M/oLMriA
         h/Jtuj8dF0MEjK17MWoiJ1QdZqRU2F+AOaX5EI93MLi5iQ4qsS5O8mkyNrFdrOCzmeY/
         ja5fLpYo4I/Fh5B2Oq91Cmd/i0eCUlBGuX4f6uZ6nnWoyZnfnud+OwILRdTdmZF03eql
         7k/g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=TalHJ9gt;
       spf=pass (google.com: domain of jiayuan.chen@linux.dev designates 91.218.175.183 as permitted sender) smtp.mailfrom=jiayuan.chen@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764853237; x=1765458037; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:in-reply-to:cc:to:subject:tls-required
         :message-id:from:content-transfer-encoding:date:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=2GQpleJNfjxdaUZ+2kToUvRbg7iGfiLwnlBal/pQUlw=;
        b=JChKDzoLCB083LXUH9UluJVWAmhRvAxO8eD/yVGMcQ8lPLqZbZ2gcz9F2/3svgCguG
         7Qr2kCi0NeUq6EH7Vf3G3xXYqAOtmCS/6ybzUcxQKg4Fb16c+WIjiCE8+QcGDK+NIScT
         Y2W34S4IJln/Uw2Zl4bL5W+UtU7ltwZ6iDjdN3S7dxK6jd0avJgVBcLGFJ5M7huRO/Pr
         hsZpHUeJVFnxyDYTF4HaMq3TzsOylZsR2dQctDS3yfDoRgrSCz7gyo6G7VBHq3O8SWjg
         ZPxE3Fqz3s+Imn5B+ifscFR5Vp+4l2JbJwg8HaAsOzGFL36pX+IqihwKViJhSoP2Xq2E
         YiKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764853237; x=1765458037;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:references
         :in-reply-to:cc:to:subject:tls-required:message-id:from
         :content-transfer-encoding:date:mime-version:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2GQpleJNfjxdaUZ+2kToUvRbg7iGfiLwnlBal/pQUlw=;
        b=KbibpLP8xeE291kEm/APV0cfFQSheru9HS3EEG08EusRIDFjbuvb3tiJIRNpyCW5By
         FGd/dtR3QxjHStp2ygh4WrIxZlHvpX3CN8A9bJx+YYXwiIBtFgepgQ/57yDFG+oDj38P
         Nef5sWIuw53jkhNT6wWSqVtyhmvHZZw9naXciZaSy26FuPVCkTHTLnlqoY0IeUv3Hukp
         Unt6ZCSBic6zoWogubZRFRIl11pACrgjZSDnCUU7WowwKL11apJVs3dvgMWFEIzGAh58
         ksYSoOu/KM8FgcwJBKgT6rIG8elEoYH7eiE5/by4WSXauWYD4CrjiACvw+Fcm/7NANry
         /QXA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXdSGhGwLr02j1vfGBQw2/ETQ2rvpG0UVY5FbbtoK2uF8jxt4ao0cPdwhVWaVLvf8vkZnxTlA==@lfdr.de
X-Gm-Message-State: AOJu0YwpO5aKi/r8tx6eHja0UhuRSSqTuTkWHa/FkagERs5hYWWT83yB
	LcmCTYvX95iiiyk4n/OTqszTW+YJFy9yxuZAFvuwWVY1nrmctnBjY4go
X-Google-Smtp-Source: AGHT+IG7yHrdNvONlHTdAQhgn2WFVOBMoeWpp/ZcBAHG4UDIWKRfFesLDTuQT+IKzRDvEjHIrKVH6g==
X-Received: by 2002:a2e:b8d1:0:b0:37b:a664:acea with SMTP id 38308e7fff4ca-37e6dda2bfcmr8021441fa.12.1764853236147;
        Thu, 04 Dec 2025 05:00:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aJPZFxIbAQyIt+K3Gtpr+pu9cFPbUUQECFXmrdT3P/7w=="
Received: by 2002:a2e:700e:0:b0:36e:6146:66fe with SMTP id 38308e7fff4ca-37e6eb5c332ls1753251fa.1.-pod-prod-09-eu;
 Thu, 04 Dec 2025 05:00:32 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXpJUj/Uix2mq8kidDc99rI5276wld8SZiF966Eein/svpZKWBXsf64UvW2VCA7uBjZRK/RCh1ths4=@googlegroups.com
X-Received: by 2002:a05:651c:b22:b0:37b:b952:5f2 with SMTP id 38308e7fff4ca-37e6ddc0b78mr7990621fa.13.1764853232392;
        Thu, 04 Dec 2025 05:00:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764853232; cv=none;
        d=google.com; s=arc-20240605;
        b=cdofk77urcF2cjaIj4vjQsbRyzCWXx/wNOK4ybsPued5GOrf1HTXyzLbvzMvXABP2h
         3Lmt6Bf0ag4DxTkIimMYP83TfcPM0uQ0a7NfQB0+P2k8B9a7qQ8RZ2Gvv4HAl6AhUPMq
         lBDL9nIBMXAXT5UTwtcrf2KSj800Un5dj5uII14nss/xldJhIP/TVSc72vgDcctoh/DV
         spsU07cszA8w2gE5JJck/c0MXD+HLxFFrN1CsPMFpOXIDD34Iush2O6TsZtwhDwkqQt1
         Okmfp5o+pq2T8poYIcfrw2oHJkG7WOHHuYt6/+Ehnc/JO3Gg2wHWYIwll4A/tQdirUQC
         5u/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=references:in-reply-to:cc:to:subject:tls-required:message-id:from
         :content-transfer-encoding:date:dkim-signature:mime-version;
        bh=G5n994p2KAdG3HNkB3DAipRjtx/VlJPO9yBG4bZMjyk=;
        fh=6H04c3vzMBumpj+m18XoCjZ8l5JFNCDoxl9vIQrxQQo=;
        b=EJ0aDwvXsW1jR+69wHej0Z2bpwEpSJVAGxJwxKJpKRbEjjHvz+jjprF+9Ko84d4UVI
         sZeYkU2dwLCsyC6uQDhzeUvXC1ltd7oDn1TavvWhcp+bUUdtYVUpKqpQl674/mcFw/6b
         6ejzPHeGPd5T4oV+kvmBd+Xpkgw3Gu3ARf8ZXh9uX1PRRMRuUfDedC+9Kugu9xIo8Hj5
         eSHhHEC7wKFtSbksaPg5rDuGc5qQoatuV3qLqk3oecDy9d7q6/kEPnGH0VGvDAAoMYr8
         +wVsuR90msUO1g4AjV6brL48b1/p3sjRiV+LAZ7G0aMPK4ZlJG2+/OMkALucGRk5ssL4
         bZ0Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=TalHJ9gt;
       spf=pass (google.com: domain of jiayuan.chen@linux.dev designates 91.218.175.183 as permitted sender) smtp.mailfrom=jiayuan.chen@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-183.mta0.migadu.com (out-183.mta0.migadu.com. [91.218.175.183])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-37e6fe49e2asi255991fa.1.2025.12.04.05.00.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Dec 2025 05:00:31 -0800 (PST)
Received-SPF: pass (google.com: domain of jiayuan.chen@linux.dev designates 91.218.175.183 as permitted sender) client-ip=91.218.175.183;
MIME-Version: 1.0
Date: Thu, 04 Dec 2025 13:00:26 +0000
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: "Jiayuan Chen" <jiayuan.chen@linux.dev>
Message-ID: <2f817f0ba6bc68d5e70309858d946597d64bac8b@linux.dev>
TLS-Required: No
Subject: Re: + mm-kasan-fix-incorrect-unpoisoning-in-vrealloc-for-kasan.patch
 added to mm-hotfixes-unstable branch
To: "Andrey Konovalov" <andreyknvl@gmail.com>, "Kees Cook" <kees@kernel.org>
Cc: mm-commits@vger.kernel.org, vincenzo.frascino@arm.com, urezki@gmail.com,
 stable@vger.kernel.org, ryabinin.a.a@gmail.com, glider@google.com,
 dvyukov@google.com, dakr@kernel.org, "kasan-dev"
 <kasan-dev@googlegroups.com>, "Maciej Wieczor-Retman"
 <maciej.wieczor-retman@intel.com>, "Andrew Morton"
 <akpm@linux-foundation.org>
In-Reply-To: <CA+fCnZeKm4uZuv2hhnSE0RrBvjw26eZFNXC6S+SPDMD0O1vvvA@mail.gmail.com>
References: <20251128185523.B995CC4CEFB@smtp.kernel.org>
 <CA+fCnZeKm4uZuv2hhnSE0RrBvjw26eZFNXC6S+SPDMD0O1vvvA@mail.gmail.com>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: jiayuan.chen@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=TalHJ9gt;       spf=pass
 (google.com: domain of jiayuan.chen@linux.dev designates 91.218.175.183 as
 permitted sender) smtp.mailfrom=jiayuan.chen@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

December 3, 2025 at 23:18, "Andrey Konovalov" <andreyknvl@gmail.com mailto:=
andreyknvl@gmail.com?to=3D%22Andrey%20Konovalov%22%20%3Candreyknvl%40gmail.=
com%3E > wrote:


>=20

> >  ------------------------------------------------------
> >  From: Jiayuan Chen <jiayuan.chen@linux.dev>
> >  Subject: mm/kasan: fix incorrect unpoisoning in vrealloc for KASAN
> >  Date: Fri, 28 Nov 2025 19:15:14 +0800
> >=20
> Hi Jiayuan,
>=20
> Please CC kasan-dev@googlegroups.com when sending KASAN patches.
>=20

Sorry about that. I missed it.

> >=20
> > Syzkaller reported a memory out-of-bounds bug [1]. This patch fixes two
> >  issues:
> >=20
> >  1. In vrealloc, we were missing the KASAN_VMALLOC_VM_ALLOC flag when
> >  unpoisoning the extended region. This flag is required to correctly
> >  associate the allocation with KASAN's vmalloc tracking.
> >=20
> >  Note: In contrast, vzalloc (via __vmalloc_node_range_noprof) explicitl=
y
> >  sets KASAN_VMALLOC_VM_ALLOC and calls kasan_unpoison_vmalloc() with it=
.
> >  vrealloc must behave consistently =E2=80=94 especially when reusing ex=
isting
> >  vmalloc regions =E2=80=94 to ensure KASAN can track allocations correc=
tly.
> >=20
> >  2. When vrealloc reuses an existing vmalloc region (without allocating=
 new
> >  pages), KASAN previously generated a new tag, which broke tag-based
> >  memory access tracking. We now add a 'reuse_tag' parameter to
> >  __kasan_unpoison_vmalloc() to preserve the original tag in such cases.
> >=20
> I think we actually could assign a new tag to detect accesses through
> the old pointer. Just gotta retag the whole region with this tag. But
> this is a separate thing; filed
> https://bugzilla.kernel.org/show_bug.cgi?id=3D220829 for this.
>=20

Thank you for your advice. I tested the following modification, and it work=
s.

	if (size <=3D alloced_size) {
-		kasan_unpoison_vmalloc(p + old_size, size - old_size,
-				       KASAN_VMALLOC_PROT_NORMAL);
+		p =3D kasan_unpoison_vmalloc(p, size,
+					   KASAN_VMALLOC_PROT_NORMAL | KASAN_VMALLOC_VM_ALLOC);
		/*
		 * No need to zero memory here, as unused memory will have
		 * already been zeroed at initial allocation time or during
		 * realloc shrink time.
		 */
		vm->requested_size =3D size;
		return (void *)p;
	}


> >=20
[...]
> Would be good to have tests for vrealloc too. Filed
> https://bugzilla.kernel.org/show_bug.cgi?id=3D220830 for this.
>=20

Thanks, I will add test for vrealloc in kasan_test_c.c.

> >=20
> > +
> >  kasan_unpoison(start, size, false);
> >  return (void *)start;
> >  }
> >  --- a/mm/vmalloc.c~mm-kasan-fix-incorrect-unpoisoning-in-vrealloc-for-=
kasan
> >  +++ a/mm/vmalloc.c
> >  @@ -4175,8 +4175,8 @@ void *vrealloc_node_align_noprof(const v
> >  * We already have the bytes available in the allocation; use them.
> >  */
> >  if (size <=3D alloced_size) {
> >  - kasan_unpoison_vmalloc(p + old_size, size - old_size,
> >  - KASAN_VMALLOC_PROT_NORMAL);
> >  + kasan_unpoison_vrealloc(p, size,
> >  + KASAN_VMALLOC_PROT_NORMAL | KASAN_VMALLOC_VM_ALLOC);
> >=20
> Orthogonal to this series, but is it allowed to call vrealloc on
> executable mappings? If so, we need to only set
> KASAN_VMALLOC_PROT_NORMAL for non-executable mappings. And
> kasan_poison_vmalloc should not be called for them as well (so we
> likely need to pass a protection flag to it to avoid exposing this
> logic).

Currently, vmalloc implicitly sets kasan_flags |=3D KASAN_VMALLOC_VM_ALLOC,=
 meaning the allocated
memory cannot be used for executable code segments. I think we could requir=
e users to explicitly
pass a flag indicating whether KASAN should be enabled =E2=80=94 this would=
 make the function=E2=80=99s intent
clearer and more explicit to the caller.

>=20
> Kees, I see you worked on vrealloc annotations, do you happen to know?
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
f817f0ba6bc68d5e70309858d946597d64bac8b%40linux.dev.
