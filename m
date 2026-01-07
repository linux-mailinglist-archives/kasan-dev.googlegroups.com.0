Return-Path: <kasan-dev+bncBC7M7IOXQAGRBJVK7PFAMGQEZ4BC4XI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 94985D003B2
	for <lists+kasan-dev@lfdr.de>; Wed, 07 Jan 2026 22:50:31 +0100 (CET)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-88a360b8096sf66814146d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Jan 2026 13:50:31 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1767822630; cv=pass;
        d=google.com; s=arc-20240605;
        b=AKPtu6v2ySYH02uUHqZ0waXiHqwXs5+JkGnlBQFUei3YYAXfRqpK75Ioc1WCb2k5vu
         TQ2i2SGFycsASiLkX6L3mClaLS7yA1MQs4ajBy2E8KPOlfBmd4ZNYBFk/v6OLjw3co6A
         eiVpRs7/IPsQFCt4mOzcn+wJW4UIM3B8+nmioKYa5DY3m7DnXG3u2JDobotLA4WRgvUl
         iR/KW1QTDo02Y7SYqqhFl306eVGaQ9VDT9Tg7d7keQ/ji9hyBgASiiT0qGSV74/LQHgv
         cZ+QgGQwnsYO4lq3xaLsy9v0u9psPEgQ5ef8mhZvRFamPzRJQt4SrTwxcWekexvPU+qH
         FaUg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7/S0vnmwyboVWpbw1rsMVAqCxkSGbRUDADeA9q6HHYc=;
        fh=THpol37eVYrXHNM8R2p51/NU8o4DO6DiAeP28mjUtEw=;
        b=An2d0g+6Lcnvqd0ZceBVRHL/Vjm0fW/dN45mCInZCDXrvSOmgb9Cg+Wegfjhfetv2N
         jqCbUK1TGuDQCNgoSDirwF8/dntm4wdY4j++J/sZvaR276gY4XMm7bQ4O6yoYT+1DPs0
         Y2VHW7cFoI/+ITrquuzgJZrz5WroMrNSKZOYEz9BS8z7bCKycZi66tZSKMmjvxYeYtTd
         0QaxR/f+KtI+zXvKCnpAberi9aB95iyE7EZMKz9kpsLYg4yKA3qpgbBLNVoEBW1c+KwO
         5sLVnT6l5xPDB2TQub1xOuq1QAWl2eNluWKyHUm1PCIGAFALrF8ZTBi4hM+ap8h4bFr9
         FkNw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=TTD5J8j4;
       arc=pass (i=1);
       spf=pass (google.com: domain of maze@google.com designates 2607:f8b0:4864:20::834 as permitted sender) smtp.mailfrom=maze@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767822630; x=1768427430; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7/S0vnmwyboVWpbw1rsMVAqCxkSGbRUDADeA9q6HHYc=;
        b=ujaEm76aRHWvoLoFek3tjMmBy8yUFJglL0UDayDX5dsA9eme4nsiDiwUWWQb1CC8LD
         XxiVw3N7MmKbVBiYQoqRWUliRvvy97nJkc1ntD1eQrhTLuRATSlQkWDBgvUD/ocdqd9q
         zK8/b4cJaK97n8Z5/3wz6/F1mQSHyZvRCojNxmRe7nBKJSpERLhCJWCTF/TIAncMz2jr
         u8FXC/jjp0KhV0/IPTiHI8AKHjYycmEKAZuszgSUUxrfmg3DJS/C87THv4Cz3uC9jgjE
         EzUAAqQrMAq30zHfSTTKSClZ18vOCRDqnPxtetKfJ0v6sm+WGc0XvxrQYSe6G96RO9Zx
         /E+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767822630; x=1768427430;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=7/S0vnmwyboVWpbw1rsMVAqCxkSGbRUDADeA9q6HHYc=;
        b=LPz8a8OxT6GWn0hh7eEhfCQWRmV+A9ia7SO+pjfnQHMlapiC0UuIX4e2tw1DrG9N2G
         ae8YkcD0d/VXKq+RuI2XymwDVIH/G0awXIdSrRRlNeqS8yAWshC5gCW87bTDigTw3u5m
         cbvosaQ27kt2y0rZ9K9bznTOzSjZZ7Ld/XpFmL2niYT5cOSOHwBlwTmxPrudQuIKYeTj
         EsXo1qWBbTFX5rI82TULH3qVtriCv9A9lA5YJdoxrxNLTWAg0ZmRvfUjukiBOMKfnMGM
         OKCvQBUoCwOI4XmweAOS4wW1ISVTzTi8Qzn5+WTYolN7N/WHGuiGZItnmb6uyZeIKotb
         bU2A==
X-Forwarded-Encrypted: i=3; AJvYcCWA+wkGnSVrkoPJrQ4lk4F/DrpDB+UnX61/7zBcgs5UPqGLLck4ITiHWdC1u5SAnHuQrMzBJQ==@lfdr.de
X-Gm-Message-State: AOJu0YzOPT6YtZu8wVo1zVMs7A7AnffmnM0NbZ12T9kiRRks9Bo58FH1
	kqmrHbj2j6BCINtWi7jpTiX5KWASSlvBCnbVmxMBUeXKVM95plib8n+J
X-Google-Smtp-Source: AGHT+IG6yIuY1Z4bXTzx4iNhXwhHCDnCUKAx4A+ioizCy2OIurpjTMwNYu/jN5PJVMNExXwups7mhg==
X-Received: by 2002:a05:6214:1304:b0:88f:cc0f:481d with SMTP id 6a1803df08f44-8908422bb1bmr60033456d6.37.1767822630250;
        Wed, 07 Jan 2026 13:50:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWa+0saU621FANGHRHyHDGDXCLaEo4FblWTZNwVPjbRZIg=="
Received: by 2002:ad4:5bc7:0:b0:886:6a14:9437 with SMTP id 6a1803df08f44-890756e43f8ls48780176d6.2.-pod-prod-07-us;
 Wed, 07 Jan 2026 13:50:29 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCWxT1TP2EL6I37l0D2xe/tmXzQdMSFxMYp8tMdf+Xsoj/6/375p2Jz+roZ++vvev0FMQgUA2FYQJRI=@googlegroups.com
X-Received: by 2002:a05:6102:419f:b0:5db:c8ab:fa56 with SMTP id ada2fe7eead31-5ecb1eaf04dmr1610416137.15.1767822629478;
        Wed, 07 Jan 2026 13:50:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767822629; cv=pass;
        d=google.com; s=arc-20240605;
        b=BnPIucvwCPgwM5HG3Gm89Xd13fQwRdJly7BZ9Vz00h5jGF5D3gzZ8XM/btccoWWfqv
         sO4vv0ceePBYou2wnt6uhz7cCavT3s7RQVOsFsmC3Ug+BNHmJSP0Ps41ZoBZbMNAMjo1
         /CPwaxh0VfoTqOkqAQWNDML8P9/YxoeF0iMoY/9QuxjnuM9VhwAZehLFNGJNqVpDDnpv
         8itmlFd+6iuY0dj8qsDPCGiLb/kMxtaL0c0sVhtHfU9ry/ooGGqOv9T9hohiUqoZobUn
         c3s+a4OpwHFmuo2hZpT3qyXu+s5OoEEcAMd5h1woQPVd82M2zNq5hegz+NeKhbq+ysF6
         Ubfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=xaOpyLcin2kj/229gqDfEx7XdNW95lzHOQ0xc5uB8Nw=;
        fh=BuAP5AbeVWo8ZzgahuQZF3Hb8yLoJdJ3KtLx8zrd4gg=;
        b=SFLY/E1XDdKFsaxenqsDRx9OC+pAmbUP348kMRuo1GTu2SNdMiMjTFKkjmAq32uaDU
         LzNn/iTb7dAp/4J8n1aLgukcZQ3qJ+JF66ha00sTg01aHGmktMLCMNVRcQmJoFQuY4en
         DC0b4RTU9+6PJ20a1NIZtAEnmTzh0SSJ5tR2Spb7MjL7Qf9jV5bEnyYGKo5Xf7x2KZgM
         piubKVj1itNd7wkWhJ+EbiUICQW6RcB7J7tKbLDW1SuMTELJk2aUHRGNXauZue+En9jR
         8plC5XrOELAjQN1/kkkcU5V38df2qGfkaDkrGP95jmXD3NvTcVJGU7refVeH3exT7Xif
         Mwbw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=TTD5J8j4;
       arc=pass (i=1);
       spf=pass (google.com: domain of maze@google.com designates 2607:f8b0:4864:20::834 as permitted sender) smtp.mailfrom=maze@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x834.google.com (mail-qt1-x834.google.com. [2607:f8b0:4864:20::834])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-9441350780csi261593241.1.2026.01.07.13.50.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 Jan 2026 13:50:29 -0800 (PST)
Received-SPF: pass (google.com: domain of maze@google.com designates 2607:f8b0:4864:20::834 as permitted sender) client-ip=2607:f8b0:4864:20::834;
Received: by mail-qt1-x834.google.com with SMTP id d75a77b69052e-4ee243b98caso533341cf.1
        for <kasan-dev@googlegroups.com>; Wed, 07 Jan 2026 13:50:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767822629; cv=none;
        d=google.com; s=arc-20240605;
        b=Gh9QCLUzzfg0dwhGVRKIryAMB8YijvyYLavEyziRqYYcKGkKy/i8saOkjaKLzhGcGn
         ovNKpCXNWKVx5b2dJdaezkWL+nza3GU6QJX59+nn6kKIQ0hU3pwVzJTt+h845V7Yb7Dd
         PubRGKfn3I6hdlD9Ng3fT+GhEyIsPHNPm4a2ieewdwRxf6MGUY8wOaIkUoPEAU+rAC2E
         Sb6at+663+NLwO+EDku82QI+zwBdeSAMJytA0nc6hycrh+EurwybV/WFxBUh2NN9XPCM
         t86/lQwBft8ajFhcJIKYJgPl23xxhkdspyzuB1IZzo3BvqalfK+8Gm8U7aFJoGQo1zif
         k7sw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=xaOpyLcin2kj/229gqDfEx7XdNW95lzHOQ0xc5uB8Nw=;
        fh=BuAP5AbeVWo8ZzgahuQZF3Hb8yLoJdJ3KtLx8zrd4gg=;
        b=B3rGHL+dWU7DLX1YzX7DKRf0AcnHM120jWf73ftBGP6kxEb9i8F4teKr3VHlDXO6Dq
         QaoKNeWwtzPzAQ4S1Z7ZJeJxA2Q6Q14ioQyJhB1Afy5TjcGxtI1FasYC57oJDz5UAsad
         Y9QaXT9fN9Qq6++4G8SSavH90pDavG9zv0OJvvp4Sn3E7xF9oK99XQo9stZo2TrKHOVN
         RyU7Ncc7spMzjFbZXC4TbjJ7LdIa7uCwbnSgCtU7bM9w//C8b7zt/xxzXPVLFCdRz+9/
         Pe4hkRjZO/c1eDP+6pvb2svaBuQE/XBvwjFBTAHyN0MzE7c2MMoJKnYteNejLwX8kjz4
         daXA==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCU77oJteuZgGBcsQrYC+8S8bDuat2kRO+MdUCMFIaGqagSx3Vuu7UvkOQ/aPxXxEaXhW4pZb/tOvBE=@googlegroups.com
X-Gm-Gg: AY/fxX7f4a4i4KaCctE4RRGIiEKwM1hUPgVjACA1EAuDTqTVmaxKMpxk9mqS5CibM0C
	yi/b9MJPqqoCdbhCg3PNazWVhPKgf+8d79uQk82dg4GJCjWZ8Q1E06TXC4aHUjoOJWbyQOs1fAM
	tW/S1viqI83cYEgdENDch5PJcMtDov5FOj4oaxgmx80JmC07GiOxQd613k/LVRSETx1MD/s9lDJ
	Dkb+d5MkldIfLdNYSPR6g447sJ1wsjUG2r8QfgDVXzKhXRafkc//f3uxjiM+0C9VHbgLfvO6k/9
	Nu8QT9c19ePGM1arFXeA8gIYhm53
X-Received: by 2002:ac8:5f8c:0:b0:4f4:bb55:68d2 with SMTP id
 d75a77b69052e-4ffc09cea00mr544121cf.12.1767822628718; Wed, 07 Jan 2026
 13:50:28 -0800 (PST)
MIME-Version: 1.0
References: <CANP3RGeuRW53vukDy7WDO3FiVgu34-xVJYkfpm08oLO3odYFrA@mail.gmail.com>
 <202601071226.8DF7C63@keescook> <btracv3snpi6l4b5upqvag6qz3j4d2k7l7qgzj665ft5m7bn22@m3y73eir2tnt>
 <CANP3RGfLXptZp6widUEyvVzicAB=dwcSx3k7MLtQozhO0NuxZw@mail.gmail.com>
In-Reply-To: <CANP3RGfLXptZp6widUEyvVzicAB=dwcSx3k7MLtQozhO0NuxZw@mail.gmail.com>
From: =?UTF-8?Q?=27Maciej_=C5=BBenczykowski=27_via_kasan=2Ddev?= <kasan-dev@googlegroups.com>
Date: Wed, 7 Jan 2026 22:50:16 +0100
X-Gm-Features: AQt7F2o8s_zvZFLLijkyWtvuzQewBbTHFYSzIOxPYFTVLuxut8PZ5Lz61l2sK0E
Message-ID: <CANP3RGeaEQipgRvk2FedpN54Rrq=fKdLs3PN4_+DThpeqQmTXA@mail.gmail.com>
Subject: Re: KASAN vs realloc
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: Kees Cook <kees@kernel.org>, joonki.min@samsung-slsi.corp-partner.google.com, 
	Andrew Morton <akpm@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Uladzislau Rezki <urezki@gmail.com>, Danilo Krummrich <dakr@kernel.org>, jiayuan.chen@linux.dev, 
	syzbot+997752115a851cb0cf36@syzkaller.appspotmail.com, 
	Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, 
	Kernel hackers <linux-kernel@vger.kernel.org>, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: maze@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=TTD5J8j4;       arc=pass
 (i=1);       spf=pass (google.com: domain of maze@google.com designates
 2607:f8b0:4864:20::834 as permitted sender) smtp.mailfrom=maze@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: =?UTF-8?Q?Maciej_=C5=BBenczykowski?= <maze@google.com>
Reply-To: =?UTF-8?Q?Maciej_=C5=BBenczykowski?= <maze@google.com>
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

On Wed, Jan 7, 2026 at 10:47=E2=80=AFPM Maciej =C5=BBenczykowski <maze@goog=
le.com> wrote:
>
> On Wed, Jan 7, 2026 at 9:47=E2=80=AFPM Maciej Wieczor-Retman
> <m.wieczorretman@pm.me> wrote:
> >
> > On 2026-01-07 at 12:28:27 -0800, Kees Cook wrote:
> > >On Tue, Jan 06, 2026 at 01:42:45PM +0100, Maciej =C5=BBenczykowski wro=
te:
> > >> We've got internal reports (b/467571011 - from CC'ed Samsung
> > >> developer) that kasan realloc is broken for sizes that are not a
> > >> multiple of the granule.  This appears to be triggered during Androi=
d
> > >> bootup by some ebpf program loading operations (a struct is 88 bytes
> > >> in size, which is a multiple of 8, but not 16, which is the granule
> > >> size).
> > >>
> > >> (this is on 6.18 with
> > >> https://lore.kernel.org/all/38dece0a4074c43e48150d1e242f8242c73bf1a5=
.1764874575.git.m.wieczorretman@pm.me/
> > >> already included)
> > >>
> > >> joonki.min@samsung-slsi.corp-partner.google.com summarized it as
> > >> "When newly requested size is not bigger than allocated size and old
> > >> size was not 16 byte aligned, it failed to unpoison extended area."
> > >>
> > >> and *very* rough comment:
> > >>
> > >> Right. "size - old_size" is not guaranteed 16-byte alignment in this=
 case.
> > >>
> > >> I think we may unpoison 16-byte alignment size, but it allowed more
> > >> than requested :(
> > >>
> > >> I'm not sure that's right approach.
> > >>
> > >> if (size <=3D alloced_size) {
> > >> - kasan_unpoison_vmalloc(p + old_size, size - old_size,
> > >> +               kasan_unpoison_vmalloc(p + old_size, round_up(size -
> > >> old_size, KASAN_GRANULE_SIZE),
> > >>       KASAN_VMALLOC_PROT_NORMAL |
> > >>       KASAN_VMALLOC_VM_ALLOC |
> > >>       KASAN_VMALLOC_KEEP_TAG);
> > >> /*
> > >> * No need to zero memory here, as unused memory will have
> > >> * already been zeroed at initial allocation time or during
> > >> * realloc shrink time.
> > >> */
> > >> - vm->requested_size =3D size;
> > >> +               vm->requested_size =3D round_up(size, KASAN_GRANULE_=
SIZE);
> > >>
> > >> my personal guess is that
> > >>
> > >> But just above the code you quoted in mm/vmalloc.c I see:
> > >>         if (size <=3D old_size) {
> > >> ...
> > >>                 kasan_poison_vmalloc(p + size, old_size - size);
>
> I assume p is presumably 16-byte aligned, but size (ie. new size) /
> old_size can presumably be odd.
>
> This means the first argument passed to kasan_poison_vmalloc() is
> potentially utterly unaligned.
>
> > >> is also likely wrong?? Considering:
> > >>
> > >> mm/kasan/shadow.c
> > >>
> > >> void __kasan_poison_vmalloc(const void *start, unsigned long size)
> > >> {
> > >>         if (!is_vmalloc_or_module_addr(start))
> > >>                 return;
> > >>
> > >>         size =3D round_up(size, KASAN_GRANULE_SIZE);
> > >>         kasan_poison(start, size, KASAN_VMALLOC_INVALID, false);
> > >> }
> > >>
> > >> This doesn't look right - if start isn't a multiple of the granule.
> > >
> > >I don't think we can ever have the start not be a granule multiple, ca=
n
> > >we?
>
> See above for why I think we can...
> I fully admit though I have no idea how this works, KASAN is not
> something I really work with.
>
> > >I'm not sure how any of this is supposed to be handled by KASAN, thoug=
h.
> > >It does seem like a round_up() is missing, though?
>
> perhaps add a:
>  BUG_ON(start & 15)
>  BUG_ON(start & (GRANULE_SIZE-1))
>
> if you think it shouldn't trigger?
>
> and/or comments/documentation about the expected alignment of the
> pointers and sizes if it cannot be arbitrary?
>
> > I assume the error happens in hw-tags mode? And this used to work becau=
se
> > KASAN_VMALLOC_VM_ALLOC was missing and kasan_unpoison_vmalloc() used to=
 do an
> > early return, while now it's actually doing the unpoisoning here?
>
> I was under the impression this was triggering with software tags.
> However, reproduction on a pixel 6 done by another Google engineer did
> indeed fail.
> It is failing on some Samsung device, but not sure what that is using...
> Maybe a Pixel 8+ would use MTE???
> So perhaps it is only hw tags???  Sorry, no idea.
> I'm not sure, this is way way lower than I've wandered in the past
> years, lately I mostly write userspace & ebpf code...
>
> Would a stack trace help?
>
> [   22.280856][  T762]
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> [   22.280866][  T762] BUG: KASAN: invalid-access in
> bpf_patch_insn_data+0x25c/0x378
> [   22.280880][  T762] Write of size 27896 at addr 43ffffc08baf14d0 by
> task netbpfload/762
> [   22.280888][  T762] Pointer tag: [43], memory tag: [54]
> [   22.280893][  T762]
> [   22.280900][  T762] CPU: 9 UID: 0 PID: 762 Comm: netbpfload
> Tainted: G           OE       6.18.0-android17-0-gef2f661f7812-4k #1
> PREEMPT  5f8baed9473d1315a96dec60171cddf4b0b35487
> [   22.280907][  T762] Tainted: [O]=3DOOT_MODULE, [E]=3DUNSIGNED_MODULE
> [   22.280909][  T762] Hardware name: Samsung xxxxxxxxx
> [   22.280912][  T762] Call trace:
> [   22.280914][  T762]  show_stack+0x18/0x28 (C)
> [   22.280922][  T762]  __dump_stack+0x28/0x3c
> [   22.280930][  T762]  dump_stack_lvl+0x7c/0xa8
> [   22.280934][  T762]  print_address_description+0x7c/0x20c
> [   22.280941][  T762]  print_report+0x70/0x8c
> [   22.280945][  T762]  kasan_report+0xb4/0x114
> [   22.280952][  T762]  kasan_check_range+0x94/0xa0
> [   22.280956][  T762]  __asan_memmove+0x54/0x88
> [   22.280960][  T762]  bpf_patch_insn_data+0x25c/0x378
> [   22.280965][  T762]  bpf_check+0x25a4/0x8ef0
> [   22.280971][  T762]  bpf_prog_load+0x8dc/0x990
> [   22.280976][  T762]  __sys_bpf+0x340/0x524
> [   22.280980][  T762]  __arm64_sys_bpf+0x48/0x64
> [   22.280984][  T762]  invoke_syscall+0x6c/0x13c
> [   22.280990][  T762]  el0_svc_common+0xf8/0x138
> [   22.280994][  T762]  do_el0_svc+0x30/0x40
> [   22.280999][  T762]  el0_svc+0x38/0x90
> [   22.281007][  T762]  el0t_64_sync_handler+0x68/0xdc
> [   22.281012][  T762]  el0t_64_sync+0x1b8/0x1bc
> [   22.281015][  T762]
> [   22.281063][  T762] The buggy address belongs to a 8-page vmalloc
> region starting at 0x43ffffc08baf1000 allocated at
> bpf_patch_insn_data+0xb0/0x378
> [   22.281088][  T762] The buggy address belongs to the physical page:
> [   22.281093][  T762] page: refcount:1 mapcount:0
> mapping:0000000000000000 index:0x0 pfn:0x8ce792
> [   22.281099][  T762] memcg:f0ffff88354e7e42
> [   22.281104][  T762] flags: 0x4300000000000000(zone=3D1|kasantag=3D0xc)
> [   22.281113][  T762] raw: 4300000000000000 0000000000000000
> dead000000000122 0000000000000000
> [   22.281119][  T762] raw: 0000000000000000 0000000000000000
> 00000001ffffffff f0ffff88354e7e42
> [   22.281125][  T762] page dumped because: kasan: bad access detected
> [   22.281129][  T762]
> [   22.281134][  T762] Memory state around the buggy address:
> [   22.281139][  T762]  ffffffc08baf7f00: 43 43 43 43 43 43 43 43 43
> 43 43 43 43 43 43 43
> [   22.281144][  T762]  ffffffc08baf8000: 43 43 43 43 43 43 43 43 43
> 43 43 43 43 43 43 43
> [   22.281150][  T762] >ffffffc08baf8100: 43 43 43 43 43 43 43 54 54
> 54 54 54 54 fe fe fe
> [   22.281155][  T762]                                         ^
> [   22.281160][  T762]  ffffffc08baf8200: fe fe fe fe fe fe fe fe fe
> fe fe fe fe fe fe fe
> [   22.281165][  T762]  ffffffc08baf8300: fe fe fe fe fe fe fe fe fe
> fe fe fe fe fe fe fe
> [   22.281170][  T762]
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> [   22.281199][  T762] Kernel panic - not syncing: KASAN: panic_on_warn s=
et ...
>
> > If that's the case, I agree, the round up seems to be missing; I can ad=
d it and
> > send a patch later.

WARNING: Actually I'm not sure if this is the *right* stack trace.
This might be on a bare 6.18 without the latest extra 4 patches.
I'm not finding a more recent stack trace.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANP3RGeaEQipgRvk2FedpN54Rrq%3DfKdLs3PN4_%2BDThpeqQmTXA%40mail.gmail.com.
