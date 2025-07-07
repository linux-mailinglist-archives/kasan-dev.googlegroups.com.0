Return-Path: <kasan-dev+bncBC3ZPIWN3EFBBI4PWHBQMGQEMKIZ72Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 576C2AFBE30
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Jul 2025 00:18:13 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id ffacd0b85a97d-3a4f7f1b932sf2396271f8f.2
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jul 2025 15:18:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751926692; cv=pass;
        d=google.com; s=arc-20240605;
        b=gyZhBExX9BbkAAD7MrevC55oHUPIwSohVqJVC/Mhl+nsrIK2uQQqqFJHoTxGKHUPAb
         HEEzP6hZ/jpuTMgzh7hgsMITuIG/hQ+EOgsehROXymxv/4KKrP0rNGwchoyAVDyOveGq
         Rf8Zs6hBC5H9suSkuOhBGA4xEXRXAT2ABBIbk8JK6pnu07+AbFyKILZNCSUMrim3DE6o
         caMIWNopLRK53G7YcM+9DfRKSUiIds4CiCXbC8D/xSdyAudepAiqYRQmHAAE+6Uu78wJ
         iPa1uVPOiuTsZQiue8C4MklCwqZcgeCgqwnaINjsoN96S+bcDzSLQSNJYlNSBUXCikuT
         Y7PA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=+sADrPzGsKcIHf+GuGPYtXHyhNJm7p2mWqkpf8Tfhts=;
        fh=43gdhrLkPBeyYE31al2Dn+dBWUmGKVoGWxzjdQ0oBPc=;
        b=WUl7Fms15QxxfTxMnlU9PBBQeR2PICd6Fu+Y22pO+8K5FxybZ24iCv4jM6EcLLZaBP
         wRxMG0jLNEwuqriNJmwNTOP0fX14QY0X8tH5VoK4rXMvkEe+7+iTAJrtUh/XAXtRfz6m
         3RgOjgL++slwPkz7X5czbox5BWsHG5sB0yIo3qm/WuCP6XLKMJqXaCahBb6UmjIAF0Mz
         H8bkD3bP2vK7K0kssDDl62bOkYIKHGp6Bzm6tHGBvMHySniymLLuY09KAdEZhdnVpIQx
         DOlUSwe1Sgo90e042VKaP7XyDZ6DWQdONg1WEQgBANHio6+5JUFBMwtebVS5obrgFsgj
         gSdw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=OOIV51ad;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::533 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751926692; x=1752531492; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+sADrPzGsKcIHf+GuGPYtXHyhNJm7p2mWqkpf8Tfhts=;
        b=vb9oSo2VKm8KPeb6yOP/4/J4blYlGJo6+N+UOzqxscb99ezrH3e5ZqZJFATfe77XnM
         b4NFmYm+wCa24ldOvySvp71HalBrjBh5fSJvlKF2+0IxpbM5/R1iBLerj1pNpRl4avHn
         ql8craXUGaA9cliyn6CUb+YX3tKVan9qmNp5sBtTWWair4DSvDe1+96BU2J1GohnqSpa
         BUC3GX1w+WOO+63cmkeAlWXndyc+oUJeyqqVLDuEXotSQbfW+IEYd9tzMQxvKr85B3TQ
         +BO3ns2mAXIC7OL6BqQBuKE3r4xi/DXOwALUijTCN8loujjBsatPW9coHiGKUb0IcXXC
         fcZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751926692; x=1752531492;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+sADrPzGsKcIHf+GuGPYtXHyhNJm7p2mWqkpf8Tfhts=;
        b=LGVqQzZoDjIzm+Yas6FYapWq5vCdVB1L4rlZcLZ4PphBbQ/AuJNZimd5Jm5DGwDDhm
         UNdldvwNhMR2hCLESRjZkThWzCZDesAAmd0t7kUIQUOpQlo1p/gnWLuvHNFepk8+1l0c
         nx8pec5xBvGdEs/zLQzH2xAbOBFciiXHX7fxcJun2okJ30hD97ny5sfHSoWjvQKQKmzx
         /MymA4AYMOr0oAk7mQ9Wz3YWYkHAGHfwwd0C0ZGz0AHLyrZkuuyoOzQv3VEhB0DsYayd
         Jfmi5k0H8BaX+YeV+pZBOgdbrn1eJ1LKhi1TGPzOqNs9wbhht6BQVkfvUhtXbibnsZ8m
         LsDw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWn81ABxcNOncqHgskFEEgflmWVon20YEycmaZMaxPPPU7hePEd2UCVIehDhrNREF6bHY3ynw==@lfdr.de
X-Gm-Message-State: AOJu0Yx19w90GQALrt2Ojgr0Le8NGoyijB1nvMZONxoaooGMA3Nv8kQn
	SkqtvRWIUc/LAirwVM+O21Zg3g4aYJNe2r67n2ayRcObNZDWXEQ5xaxt
X-Google-Smtp-Source: AGHT+IEaEmidD9Xtb+wSKpihUQN8CzlXo5i811TD+pcE+cYjLR5Wnp3/sYK7jnF0SkDWQJ+srSiV/g==
X-Received: by 2002:a05:6000:4022:b0:3a5:27ba:47c7 with SMTP id ffacd0b85a97d-3b49702ea79mr12987171f8f.48.1751926692388;
        Mon, 07 Jul 2025 15:18:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdGW5hWx8tCD6E922FI0WPJsXFqb3fVRBCDefEzsTDyRw==
Received: by 2002:a05:600c:1f08:b0:43c:edda:8108 with SMTP id
 5b1f17b1804b1-454b5cf7be2ls17406795e9.1.-pod-prod-07-eu; Mon, 07 Jul 2025
 15:18:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXvsuWL1d5/4QcIlvQSjU1Zsf3e+psJoDMCTl2oDuM2z/wTHxbT5lsM8zNsLh5MiEnF3gYSg6mMWWE=@googlegroups.com
X-Received: by 2002:a05:6000:4022:b0:3a6:e1e7:2a88 with SMTP id ffacd0b85a97d-3b497037a9amr12278483f8f.57.1751926689300;
        Mon, 07 Jul 2025 15:18:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751926689; cv=none;
        d=google.com; s=arc-20240605;
        b=ZR4MHywrbNWV4wp0sW1Yf3z3zYq1uUbRlJSoeQ5m/59A5saZHfkonzLmizQXjpCDk2
         8j+DZ9QCTZn/+UR+Y1SpS2t41aE+/lyTU49jeNJQuD8dPo3l0lvBT5lWbU31f3IlOLP/
         ouq5cFBpNlIWoM7/6XgIm4zlqeKPJ4/da9nUx4sSWhO/Fy29P7DBS3I2Xc6RWLe1dr0N
         cf/yBF4VvN3+YgH4y46SbbCqEOh8morw8+9++ZaKXJsY/5VGxr0ZxgTvUGAC1qQ6rOde
         QiBs66stBl/JNnTsVdQu6zD82/7RZFeZYGx9t1H+44CHorKLamb/phFsivz4604MU0hg
         w+nA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vUqqsbRlIl+0KIYJcUROFT1sVqNppMFyhgNr/RPU0Ys=;
        fh=q8COM4xWRmRyFNGrpXEIaq+utVfEar79YJOLkzfDURc=;
        b=FSE9+DPqBgIlnqfGde/uWcFRAvrEfiBwtsIZKz3+ShbFCYIoAy66JdOinDXFTXDvI/
         KW3Cbft1Yt8eVjf2Hq7QhfSiAxXyX4OkcVZJVn+JzHhogSEKp3q/UjdWotAnXSsvnX5t
         DHz3Qzt5/HxoaIJ2EDwawv9awgLrr4kw5mrBIv9CgAzhdTQJfkJnAobZ6eXKSWza6TkO
         5Zg8M+YXipNcuZzXOhhMlh9oA+ivRQnSyeVocivHl+vCdSuoaj0ELq4b1Y1NRUa+QmmV
         APjeeXHsJo8/K1imEz3PJeh/Q2OqSD72txPsIGw28yAkQyRJv3NAJBKaNHJLXoVnR+Ka
         jKxQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=OOIV51ad;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::533 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x533.google.com (mail-ed1-x533.google.com. [2a00:1450:4864:20::533])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b4718a5ac8si128258f8f.5.2025.07.07.15.18.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Jul 2025 15:18:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::533 as permitted sender) client-ip=2a00:1450:4864:20::533;
Received: by mail-ed1-x533.google.com with SMTP id 4fb4d7f45d1cf-60707b740a6so5000620a12.0
        for <kasan-dev@googlegroups.com>; Mon, 07 Jul 2025 15:18:09 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWtmm1lSweQk7+Seoorh25m4bMVQluqgDBsv83cCK3NRgkpZu1idm7G3xA85iLK+xKG8rwtgPJdECY=@googlegroups.com
X-Gm-Gg: ASbGncsMyaVCeWUD7r5j00NlZ831xAW5T7wttwhZhcC2cGLeV45TUeAwDwgWP+skY01
	Woflxb7Ibp6z9U1yJcHdu2o6IlOKfV+Uc8NXdDgsoKA+xs0f1k6gie08RAi+iQ3aXwT0/Wj/0F7
	Hxj+wJVqY+xXhKwSjfOSg6mCMLvBGalQU3JDV/WejCvLekXL6mgM+m/9h+/k9R6R8SPB0C8Gogn
	7lMEIgTm0UfpDNNSzegCD+WVDcdjF4M2U1VCWWNcQmmrHgx89vM4M/ltP1FQ4S3bWi5z9QbBUyf
	O7N+5bUqGQWE8veXOWuETfPenUBz0/SRmwJovexE6zVU5JKVlWosE69VTpjo+yMQ7c649ROs8nT
	O90rMFAiA6l59eUKE6ayFNvHcUSX1VYiqTDnWX7/MHf1iu/s=
X-Received: by 2002:a05:6402:26c2:b0:606:f836:c657 with SMTP id 4fb4d7f45d1cf-60fd6d97fabmr13246918a12.28.1751926688526;
        Mon, 07 Jul 2025 15:18:08 -0700 (PDT)
Received: from mail-ed1-f41.google.com (mail-ed1-f41.google.com. [209.85.208.41])
        by smtp.gmail.com with ESMTPSA id 4fb4d7f45d1cf-60fcb0c78efsm6377996a12.44.2025.07.07.15.18.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Jul 2025 15:18:07 -0700 (PDT)
Received: by mail-ed1-f41.google.com with SMTP id 4fb4d7f45d1cf-6077dea37easo6037696a12.3
        for <kasan-dev@googlegroups.com>; Mon, 07 Jul 2025 15:18:06 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU+HZ00qJgsXPpvDa14/olxE8NywuzWuKjxtkP/FKk5cHAymKE2V/vurSpcPMTxolUK88rfbXfa0q4=@googlegroups.com
X-Received: by 2002:a05:6402:2356:b0:60c:461e:71c0 with SMTP id
 4fb4d7f45d1cf-60fd6e04c9emr12735823a12.30.1751926686474; Mon, 07 Jul 2025
 15:18:06 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1751862634.git.alx@kernel.org> <033bf00f1fcf808245ae150346019aa7b997ea11.1751862634.git.alx@kernel.org>
 <CAHk-=wh9Pqz07ne9iSt1_v0c14rkOGvF9AbEkaq1KnFhQD1SSA@mail.gmail.com>
 <ugf4pu7qrojegz7arkcpa4cyde6hoyh73h66oc4f6ncc7jg23t@bklkbbotyzvp>
 <CAHk-=whQ_0qFvg3cugt84+iKXi_eebNGY4so+PSnyyVNGVde1A@mail.gmail.com>
 <gjxc2cxjlsnccopdghektco2oulmhyhonigy7lwsaqqcbn62wj@wa3tidbvpyvk> <r43lulact3247k23clhbqnp3ms75vykf7yxa526agenq2b4osk@q6qp7hk7efo2>
In-Reply-To: <r43lulact3247k23clhbqnp3ms75vykf7yxa526agenq2b4osk@q6qp7hk7efo2>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Mon, 7 Jul 2025 15:17:50 -0700
X-Gmail-Original-Message-ID: <CAHk-=wj6gEmYih1VfYZu9FiYtOJYSFQ0f45CQZtDLrJpzF47Bg@mail.gmail.com>
X-Gm-Features: Ac12FXx7EVbwgcu_kwWLSiLwlTlYjfwq5vvQwKm9O0uZQ7guWOwdxI-MvQMXh0I
Message-ID: <CAHk-=wj6gEmYih1VfYZu9FiYtOJYSFQ0f45CQZtDLrJpzF47Bg@mail.gmail.com>
Subject: Re: [RFC v3 3/7] mm: Use seprintf() instead of less ergonomic APIs
To: Alejandro Colomar <alx@kernel.org>
Cc: linux-mm@kvack.org, linux-hardening@vger.kernel.org, 
	Kees Cook <kees@kernel.org>, Christopher Bazley <chris.bazley.wg14@gmail.com>, 
	shadow <~hallyn/shadow@lists.sr.ht>, linux-kernel@vger.kernel.org, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Sven Schnelle <svens@linux.ibm.com>, 
	Heiko Carstens <hca@linux.ibm.com>, Tvrtko Ursulin <tvrtko.ursulin@igalia.com>, 
	"Huang, Ying" <ying.huang@intel.com>, Lee Schermerhorn <lee.schermerhorn@hp.com>, 
	Christophe JAILLET <christophe.jaillet@wanadoo.fr>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	Chao Yu <chao.yu@oppo.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b=OOIV51ad;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::533 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
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

On Mon, 7 Jul 2025 at 14:27, Alejandro Colomar <alx@kernel.org> wrote:
>
> If the name is your main concern, we can discuss a more explicit name in
> the kernel.

So as they say: "There are only two hard problems in computer science:
cache invalidation, naming and off-by-one errors".

And the *worst* model for naming is the "add random characters" (ok, I
still remember when people believed the insane "Hungarian Notation"
BS, *that* particular braindamage seems to thankfully have faded away
and was probably even worse, because it was both pointless, unreadable
_and_ caused long identifiers).

Now, we obviously tend to have the usual bike-shedding discussions
that come from naming, but my *personal* preference is to avoid the
myriad of random "does almost the same thing with different
parameters" by using generics.

This is actually something that the kernel has done for decades, with
various odd macro games - things like "get_user()" just automatically
doing the RightThing(tm) based on the size of the argument, rather
than having N different versions for different types.

So we actually have a fair number of "generics" in the kernel, and
while admittedly the header file contortions to implement them can
often be horrendous - the *use* cases tend to be fairly readable.

It's not just get_user() and friends, it's things like our
type-checking min/max macros etc. Lots of small helpers that

And while the traditional C model for this is indeed macro games with
sizeof() and other oddities, these days at least we have _Generic() to
help.

So my personal preference would actually be to not make up new names
at all, but just have the normal names DoTheRightThing(tm)
automatically.

But honestly, that works best when you have good data structure
abstraction - *not* when you pass just random "char *" pointers
around.  It tends to help those kinds of _Generic() users, but even
without the use of _Generic() and friends, it helps static type
checking and makes things much less ambiguous even in general.

IOW, there's never any question about "is this string the source or
the destination?" or "is this the start or the end of the buffer", if
you just have a struct with clear naming that contains the arguments.

And while C doesn't have named arguments, it *does* have named
structure initializers, and we use them pretty religiously in the
kernel. Exactly because it helps so much both for readability and for
stability (ie it catches things when you intentionally rename members
because the semantics changed).

                Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3Dwj6gEmYih1VfYZu9FiYtOJYSFQ0f45CQZtDLrJpzF47Bg%40mail.gmail.com.
