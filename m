Return-Path: <kasan-dev+bncBAABBWNZY3EQMGQEIO7DCXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 972DFCA40C3
	for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 15:38:18 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-47777158a85sf11480315e9.3
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 06:38:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764859098; cv=pass;
        d=google.com; s=arc-20240605;
        b=asCzOPuLdhpzodXVrRu0aPNJIkrxZC9MqOmgHcpGsx+KgyHtWmHonxOkOgXQNBEElM
         Ez2YuZvBS2TcaoaE5Qt0jnyyQan/gQABlBhGMBYjCe8Yik/v1fd4vQcbLi5//dCNHQPn
         pKMeg29qTAAIlRu34AkbeT016arzmSO86cwNlnFvIjxSYfVj/+EAogHwJmUwW/ncGNsM
         XOZV52EW3T2V3OCcOQs28IY2wmxvntjEvmXqlvmUwBzhXJlppinQ82Htb874mVZTier8
         NIHkRsGsylYxGKEQEfK+IcLFu1V1hLroKsIVFGuvcu5wZhKY1x3a5rh+JWFa0us8XLDL
         5Kwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:cc:to
         :subject:tls-required:message-id:from:content-transfer-encoding:date
         :mime-version:sender:dkim-signature;
        bh=1Lg2zKCYzIiI9wgVNDqARKxj67CrhzQTrW5ZMyaCycI=;
        fh=xNMMf+e3dmzlcgsocPJr8iXP1QSz27K8pAq5cTVitKs=;
        b=OufKr/4QZzR8C4NX2Mqj+z9EgAHr+/UYmozO0PRulys5s9Q7R5xiPEa4IKl6cB0N/m
         YYFWrdi9hYBjlt2k7+Rij8XrqHC2y+zqjFaMXZvM0EiThBFW6Uz+S+0lfoPu2GDmkuuT
         7IExzBIm5pAfRkk0/zFDGk96B8g7yQlmVYW5djWC8ZSkio0oIJ/a1MNYyA2Voqls6VbA
         Yk0KsWbJDIuxV0H58E/NuEtGfYuY5Arw6jbksnZRzwUxoNrRqspZYejx34jzaCIRp4yx
         tLzkDcVLs6u2CbYJsnIQmiN3gKdKCsJyvmNb2aO9QHUK60QqD/vAP1D5TzD3o6fndJvy
         vDEw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=JM4wZYbS;
       spf=pass (google.com: domain of jiayuan.chen@linux.dev designates 2001:41d0:203:375::bb as permitted sender) smtp.mailfrom=jiayuan.chen@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764859098; x=1765463898; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:in-reply-to:cc:to:subject:tls-required
         :message-id:from:content-transfer-encoding:date:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=1Lg2zKCYzIiI9wgVNDqARKxj67CrhzQTrW5ZMyaCycI=;
        b=VCAqrvE8UHalosKfag/EtodycSYfKppP31io3iHcUoYERL0KUDvvei3YjRC0+1ioA3
         7pRVIgWAccma1E8U3vycvHxWIl0zjI6eR7FT6TPfs66Qw/OSRE886wsGiVsDr80i3Y0r
         X72wkgKIcn+gbRLg7R61ZI0VEW+0nALtO/LLka1xqf0VT8FcLhX2ss17G8aJPadF5IYK
         dU6nw9BYqjU6dY69FcqODsWzwiLw8ANPk1GfmESaTgo5yYKPwoZgZXucQGjWIbWGRLb7
         h19zxLWWBr9GyY1jkrKowNGRFVWY3SDJ3MPQN1F8jCdh8z9eL8cC/c9lBrJAyCNCRwaA
         jfjQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764859098; x=1765463898;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:references
         :in-reply-to:cc:to:subject:tls-required:message-id:from
         :content-transfer-encoding:date:mime-version:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1Lg2zKCYzIiI9wgVNDqARKxj67CrhzQTrW5ZMyaCycI=;
        b=FeS8/fZ5DBfpnOJbwczo3+pdQiBp9qrs0o9rPNh6MbIEFcB3eobneS10OlxLO1ESeM
         /186lydgr7icm3aL7DJ6ccjppm/yOl9xsAeArQtnKikgV+liOxmioQUPrZVKXra9nRHg
         P7wl9Lc1+TmySRB5hr4kIk29+kQ4Ih2yge8nhNT2enM6/Qp8KQvg28uF6rC7A6qBtofX
         1IDYvClQSJ70BR8mmU1jC5DegCYTkTg7GUFtI+xTQLVGpCUFymPJWVsXN7koxa0oKVd4
         Iq3uDod8F+EbTUvoPZJ3Pr4J6XYp2b1GSbIl+3sFLqAV7qpzHIer3Ln1fsPU0gaV6SdW
         WcNQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWaOaxuTJtaFegCiTNO5blXRuXprSaTC3TRIm8Cbf6RIpEn1REnbHeFIMWqzyD38yryqAlDHA==@lfdr.de
X-Gm-Message-State: AOJu0YwLQfEN+s92eA1itLSei4xnNai8NeVnl8axaSF/Cnn1nx4aVSGg
	BxCF9VGrODS/3zznewjXw1DrkjBEUHF9wbobMdgiYz79SZoqjolGEKqi
X-Google-Smtp-Source: AGHT+IEb53q5wZg7jfhhl0wSys2nWYE7U6UEBJkSQpFDzobj/t2N7PbPVzn9KzIM98VyzBTW05FMgg==
X-Received: by 2002:a05:600c:4449:b0:477:5ad9:6df1 with SMTP id 5b1f17b1804b1-4792aedfe2bmr74514435e9.3.1764859097793;
        Thu, 04 Dec 2025 06:38:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aT7tQap+9GEYjFKWVlW892MYZAP8yHJGmbMj0SWFoYHQ=="
Received: by 2002:a05:600c:c48e:b0:477:980b:bae9 with SMTP id
 5b1f17b1804b1-4792fb6232bls4621955e9.0.-pod-prod-05-eu; Thu, 04 Dec 2025
 06:38:16 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXF99Gz+YCb1G1AMEwAhJt2WB0l9em5d2DcwtWO8O9Sp6mQhkSroEonyTf+RpdxNsz1xQHJhjuivQA=@googlegroups.com
X-Received: by 2002:a05:600c:4443:b0:477:9b35:3e36 with SMTP id 5b1f17b1804b1-4792aedfbf4mr67423645e9.2.1764859095781;
        Thu, 04 Dec 2025 06:38:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764859095; cv=none;
        d=google.com; s=arc-20240605;
        b=X9CBhrMjjK8N1rjbqCzYkmOoqM5gJszNZJNFoRTbE5DQFop+5K+9O6wpU3cKWbqNu8
         XG2YRgPyjJ9zfie4D9aGFPGuoLa7lEn3P5JBHJkaDke/rACPrdqn1PFT4TDpr2YYqfIU
         NKlMGGkYdPEv4SzsnxLNtPwWtczZsrOOKu36hq9u4Iq1pCePkh2Rpx/mOUHeOl0/ZCXG
         KOkEdWJTfFjiuxr7tEtncXrid3hYsvyPNaOK0JN6fGxeHjIkRNUL3qzukwn1MDUe8Y46
         cKQOHwbfF3fSstFWeF7zn8HcuKyboAK17xctSBq7RIUh/R9Kc2Gz+ouLmbzEu/02VRBq
         5mSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=references:in-reply-to:cc:to:subject:tls-required:message-id:from
         :content-transfer-encoding:date:dkim-signature:mime-version;
        bh=oyv8T3zljC5amsZPaB9Pcte8dRSYUhsdKHtrFYp3ltI=;
        fh=eGgcKFHJ9pR9tX2sxCj+06VlggNPys59egbVflYCb3s=;
        b=dqoBPnZgxFlusb8C9pbdg4VNoRongbI07M9U4LmJ3EfPm5uUZyUJQXXrurGqNsrjCO
         QmTk9Yes2FwIZS3MhwtA4NnkI63PfaEUILMlpTx1r3GpnaaeGu0Brvtg3vSqZqwWiRiu
         +3VpKK4vt30q7k/gw8gyjQaEKdbOW82aayeno30W1sAqyqKwT3U7B++0Ai+nwZ6lCZq8
         f02RrJ+SJgvNkGYMENbjzs0YDvZFa0PwUHYXgYOMNwlJh73JHmiAC1uIu9w/DHujCweP
         R8t/5U158++D2CiHXqf8VJnpJeZRO0qSklFIv2eXzclQ/Yc+rPtn4cnQg+oh/tI2wjAX
         YCtQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=JM4wZYbS;
       spf=pass (google.com: domain of jiayuan.chen@linux.dev designates 2001:41d0:203:375::bb as permitted sender) smtp.mailfrom=jiayuan.chen@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-187.mta1.migadu.com (out-187.mta1.migadu.com. [2001:41d0:203:375::bb])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-42f7cbeacb7si37025f8f.3.2025.12.04.06.38.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Dec 2025 06:38:15 -0800 (PST)
Received-SPF: pass (google.com: domain of jiayuan.chen@linux.dev designates 2001:41d0:203:375::bb as permitted sender) client-ip=2001:41d0:203:375::bb;
MIME-Version: 1.0
Date: Thu, 04 Dec 2025 14:38:12 +0000
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: "Jiayuan Chen" <jiayuan.chen@linux.dev>
Message-ID: <ef40d7bb8d28a5cde0547945a0a44e05b56d0e76@linux.dev>
TLS-Required: No
Subject: Re: [PATCH v1] mm/kasan: Fix incorrect unpoisoning in vrealloc for
 KASAN
To: "Maciej Wieczor-Retman" <m.wieczorretman@pm.me>
Cc: "Maciej Wieczor-Retman" <maciej.wieczor-retman@intel.com>,
 linux-mm@kvack.org,
 syzbot+997752115a851cb0cf36@syzkaller.appspotmail.com, "Andrey Ryabinin"
 <ryabinin.a.a@gmail.com>, "Alexander Potapenko" <glider@google.com>,
 "Andrey Konovalov" <andreyknvl@gmail.com>, "Dmitry Vyukov"
 <dvyukov@google.com>, "Vincenzo Frascino" <vincenzo.frascino@arm.com>,
 "Andrew Morton" <akpm@linux-foundation.org>, "Uladzislau Rezki"
 <urezki@gmail.com>, "Danilo Krummrich" <dakr@kernel.org>, "Kees Cook"
 <kees@kernel.org>, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org
In-Reply-To: <5o7owlr4ap5fridqlkerrnuvwwlgldr35gvkcf6df4fufatrr6@yn5rmfn54i62>
References: <5o7owlr4ap5fridqlkerrnuvwwlgldr35gvkcf6df4fufatrr6@yn5rmfn54i62>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: jiayuan.chen@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=JM4wZYbS;       spf=pass
 (google.com: domain of jiayuan.chen@linux.dev designates 2001:41d0:203:375::bb
 as permitted sender) smtp.mailfrom=jiayuan.chen@linux.dev;       dmarc=pass
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

December 4, 2025 at 21:55, "Maciej Wieczor-Retman" <m.wieczorretman@pm.me m=
ailto:m.wieczorretman@pm.me?to=3D%22Maciej%20Wieczor-Retman%22%20%3Cm.wiecz=
orretman%40pm.me%3E > wrote:


>=20
> On 2025-12-03 at 02:05:11 +0000, Jiayuan Chen wrote:
>=20
> >=20
> > December 3, 2025 at 04:48, "Maciej Wieczor-Retman" <maciej.wieczor-retm=
an@intel.com mailto:maciej.wieczor-retman@intel.com?to=3D%22Maciej%20Wieczo=
r-Retman%22%20%3Cmaciej.wieczor-retman%40intel.com%3E > wrote:
> >=20
> > >=20
> > > Hi, I'm working on [1]. As Andrew pointed out to me the patches are q=
uite
> > >  similar. I was wondering if you mind if the reuse_tag was an actual =
tag value?
> > >  Instead of just bool toggling the usage of kasan_random_tag()?
> > > =20
> > >  I tested the problem I'm seeing, with your patch and the tags end up=
 being reset.
> > >  That's because the vms[area] pointers that I want to unpoison don't =
have a tag
> > >  set, but generating a different random tag for each vms[] pointer cr=
ashes the
> > >  kernel down the line. So __kasan_unpoison_vmalloc() needs to be call=
ed on each
> > >  one but with the same tag.
> > > =20
> > >  Arguably I noticed my series also just resets the tags right now, bu=
t I'm
> > >  working to correct it at the moment. I can send a fixed version tomo=
rrow. Just
> > >  wanted to ask if having __kasan_unpoison_vmalloc() set an actual pre=
defined tag
> > >  is a problem from your point of view?
> > > =20
> > >  [1] https://lore.kernel.org/all/cover.1764685296.git.m.wieczorretman=
@pm.me/
> > >=20
> > Hi Maciej,
> >=20
> > It seems we're focusing on different issues, but feel free to reuse or =
modify the 'reuse_tag'.
> > It's intended to preserve the tag in one 'vma'.
> >=20
> > I'd also be happy to help reproduce and test your changes to ensure the=
 issue I encountered
> > isn't regressed once you send a patch based on mine.=20
> >=20
> > Thanks.
> >=20
> After reading Andrey's comments on your patches and mine I tried applying=
 all
> the changes to test the flag approach. Now my patches don't modify any vr=
ealloc
> related code. I came up with something like this below from your patch. J=
ust
> tested it and it works fine on my end, does it look okay to you?
>=20
> ---
>  include/linux/kasan.h | 1 +
>  mm/kasan/hw_tags.c | 3 ++-
>  mm/kasan/shadow.c | 4 +++-
>  mm/vmalloc.c | 6 ++++--
>  4 files changed, 10 insertions(+), 4 deletions(-)
>=20
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 03e263fb9fa1..068f62d07122 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -28,6 +28,7 @@ typedef unsigned int __bitwise kasan_vmalloc_flags_t;
>  #define KASAN_VMALLOC_INIT ((__force kasan_vmalloc_flags_t)0x01u)
>  #define KASAN_VMALLOC_VM_ALLOC ((__force kasan_vmalloc_flags_t)0x02u)
>  #define KASAN_VMALLOC_PROT_NORMAL ((__force kasan_vmalloc_flags_t)0x04u)
> +#define KASAN_VMALLOC_KEEP_TAG ((__force kasan_vmalloc_flags_t)0x08u)
> =20
>  #define KASAN_VMALLOC_PAGE_RANGE 0x1 /* Apply exsiting page range */
>  #define KASAN_VMALLOC_TLB_FLUSH 0x2 /* TLB flush */
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 1c373cc4b3fa..e6d7ee544c28 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -361,7 +361,8 @@ void *__kasan_unpoison_vmalloc(const void *start, uns=
igned long size,
>  return (void *)start;
>  }
> =20
> - tag =3D kasan_random_tag();
> + tag =3D (flags & KASAN_VMALLOC_KEEP_TAG) ? get_tag(start) :
> + kasan_random_tag();
>  start =3D set_tag(start, tag);
> =20
>  /* Unpoison and initialize memory up to size. */
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index 5d2a876035d6..6dd61093d1d5 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -648,7 +648,9 @@ void *__kasan_unpoison_vmalloc(const void *start, uns=
igned long size,
>  !(flags & KASAN_VMALLOC_PROT_NORMAL))
>  return (void *)start;
> =20
> - start =3D set_tag(start, kasan_random_tag());
> + if (!(flags & KASAN_VMALLOC_KEEP_TAG))
> + start =3D set_tag(start, kasan_random_tag());
> +
>  kasan_unpoison(start, size, false);
>  return (void *)start;
>  }
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index ead22a610b18..c939dc04baa5 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -4180,8 +4180,10 @@ void *vrealloc_node_align_noprof(const void *p, si=
ze_t size, unsigned long align
>  * We already have the bytes available in the allocation; use them.
>  */
>  if (size <=3D alloced_size) {
> - kasan_unpoison_vmalloc(p + old_size, size - old_size,
> - KASAN_VMALLOC_PROT_NORMAL);
> + kasan_unpoison_vmalloc(p, size,
> + KASAN_VMALLOC_PROT_NORMAL |
> + KASAN_VMALLOC_VM_ALLOC |
> + KASAN_VMALLOC_KEEP_TAG);
>  /*
>  * No need to zero memory here, as unused memory will have
>  * already been zeroed at initial allocation time or during
>=20
> --=20
> Kind regards
> Maciej Wiecz=C3=B3r-Retman
>


I think I don't need KEEP_TAG flag anymore, following patch works well and =
all kasan tests run successfully
with CONFIG_KASAN_SW_TAGS/CONFIG_KASAN_HW_TAGS/CONFIG_KASAN_GENERIC


diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 1c373cc4b3fa..8b819a9b2a27 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -394,6 +394,11 @@ void __kasan_poison_vmalloc(const void *start, unsigne=
d long size)
 	 * The physical pages backing the vmalloc() allocation are poisoned
 	 * through the usual page_alloc paths.
 	 */
+	if (!is_vmalloc_or_module_addr(start))
+		return;
+
+	size =3D round_up(size, KASAN_GRANULE_SIZE);
+	kasan_poison(start, size, KASAN_VMALLOC_INVALID, false);
 }

 #endif
diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
index 2cafca31b092..a5f683c3abde 100644
--- a/mm/kasan/kasan_test_c.c
+++ b/mm/kasan/kasan_test_c.c
@@ -1840,6 +1840,84 @@ static void vmalloc_helpers_tags(struct kunit *test)
 	vfree(ptr);
 }

+
+static void vrealloc_helpers(struct kunit *test, bool tags)
+{
+	char *ptr;
+	size_t size =3D PAGE_SIZE / 2 - KASAN_GRANULE_SIZE - 5;
+
+	if (!kasan_vmalloc_enabled())
+		kunit_skip(test, "Test requires kasan.vmalloc=3Don");
+
+	ptr =3D (char *)vmalloc(size);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+
+	OPTIMIZER_HIDE_VAR(ptr);
+
+	size +=3D PAGE_SIZE / 2;
+	ptr =3D vrealloc(ptr, size, GFP_KERNEL);
+	/* Check that the returned pointer is tagged. */
+	if (tags) {
+		KUNIT_EXPECT_GE(test, (u8)get_tag(ptr), (u8)KASAN_TAG_MIN);
+		KUNIT_EXPECT_LT(test, (u8)get_tag(ptr), (u8)KASAN_TAG_KERNEL);
+	}
+	/* Make sure in-bounds accesses are valid. */
+	ptr[0] =3D 0;
+	ptr[size - 1] =3D 0;
+
+	/* Make sure exported vmalloc helpers handle tagged pointers. */
+	KUNIT_ASSERT_TRUE(test, is_vmalloc_addr(ptr));
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, vmalloc_to_page(ptr));
+
+	size -=3D PAGE_SIZE / 2;
+	ptr =3D vrealloc(ptr, size, GFP_KERNEL);
+
+	/* Check that the returned pointer is tagged. */
+	KUNIT_EXPECT_GE(test, (u8)get_tag(ptr), (u8)KASAN_TAG_MIN);
+	KUNIT_EXPECT_LT(test, (u8)get_tag(ptr), (u8)KASAN_TAG_KERNEL);
+
+	/* Make sure exported vmalloc helpers handle tagged pointers. */
+	KUNIT_ASSERT_TRUE(test, is_vmalloc_addr(ptr));
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, vmalloc_to_page(ptr));
+
+
+	/* This access must cause a KASAN report. */
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr)[size + 5]);
+
+
+#if !IS_MODULE(CONFIG_KASAN_KUNIT_TEST)
+	{
+		int rv;
+
+		/* Make sure vrealloc'ed memory permissions can be changed. */
+		rv =3D set_memory_ro((unsigned long)ptr, 1);
+		KUNIT_ASSERT_GE(test, rv, 0);
+		rv =3D set_memory_rw((unsigned long)ptr, 1);
+		KUNIT_ASSERT_GE(test, rv, 0);
+	}
+#endif
+
+	vfree(ptr);
+}
+
+static void vrealloc_helpers_tags(struct kunit *test)
+{
+	/* This test is intended for tag-based modes. */
+	KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_KASAN_GENERIC);
+
+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_VMALLOC);
+	vrealloc_helpers(test, true);
+}
+
+static void vrealloc_helpers_generic(struct kunit *test)
+{
+	/* This test is intended for tag-based modes. */
+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_GENERIC);
+
+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_VMALLOC);
+	vrealloc_helpers(test, false);
+}
+
 static void vmalloc_oob(struct kunit *test)
 {
 	char *v_ptr, *p_ptr;
@@ -2241,6 +2319,8 @@ static struct kunit_case kasan_kunit_test_cases[] =3D=
 {
 	KUNIT_CASE_SLOW(kasan_atomics),
 	KUNIT_CASE(vmalloc_helpers_tags),
 	KUNIT_CASE(vmalloc_oob),
+	KUNIT_CASE(vrealloc_helpers_tags),
+	KUNIT_CASE(vrealloc_helpers_generic),
 	KUNIT_CASE(vmap_tags),
 	KUNIT_CASE(vm_map_ram_tags),
 	KUNIT_CASE(match_all_not_assigned),
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 798b2ed21e46..9ba2e8a346d6 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -4128,6 +4128,7 @@ EXPORT_SYMBOL(vzalloc_node_noprof);
 void *vrealloc_node_align_noprof(const void *p, size_t size, unsigned long=
 align,
 				 gfp_t flags, int nid)
 {
+	asan_vmalloc_flags_t flags;
 	struct vm_struct *vm =3D NULL;
 	size_t alloced_size =3D 0;
 	size_t old_size =3D 0;
@@ -4158,25 +4159,26 @@ void *vrealloc_node_align_noprof(const void *p, siz=
e_t size, unsigned long align
 			goto need_realloc;
 	}

+	flags =3D KASAN_VMALLOC_PROT_NORMAL | KASAN_VMALLOC_VM_ALLOC;
 	/*
 	 * TODO: Shrink the vm_area, i.e. unmap and free unused pages. What
 	 * would be a good heuristic for when to shrink the vm_area?
 	 */
-	if (size <=3D old_size) {
+	if (p && size <=3D old_size) {
 		/* Zero out "freed" memory, potentially for future realloc. */
 		if (want_init_on_free() || want_init_on_alloc(flags))
 			memset((void *)p + size, 0, old_size - size);
 		vm->requested_size =3D size;
-		kasan_poison_vmalloc(p + size, old_size - size);
+		kasan_poison_vmalloc(p, alloced_size);
+		p =3D kasan_unpoison_vmalloc(p, size, flags);
 		return (void *)p;
 	}

 	/*
 	 * We already have the bytes available in the allocation; use them.
 	 */
-	if (size <=3D alloced_size) {
-		kasan_unpoison_vmalloc(p + old_size, size - old_size,
-				       KASAN_VMALLOC_PROT_NORMAL);
+	if (p && size <=3D alloced_size) {
+		p =3D kasan_unpoison_vmalloc(p, size, flags);
 		/*
 		 * No need to zero memory here, as unused memory will have
 		 * already been zeroed at initial allocation time or during

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/e=
f40d7bb8d28a5cde0547945a0a44e05b56d0e76%40linux.dev.
