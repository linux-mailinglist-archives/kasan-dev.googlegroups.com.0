Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBF4RVS2QMGQEL57YMIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id A1EB294421E
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Aug 2024 06:01:28 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-4280645e3e0sf39057295e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Jul 2024 21:01:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722484888; cv=pass;
        d=google.com; s=arc-20160816;
        b=ulklHopU6pByECoHD7EL0LWvhfXHi+zMuUU2AqaX7H11KiR3S3Nm54f0R4LN9me9qN
         /PNXaeouEuQX+iCn6drXbZl3JgVbVLzMgSO4A7OWfLfYf4uKd2y1sR1GSnICEseUVurB
         /v0y9bnHlkUXyJl8M8zKGUptd3KgJd79bsqaybmXgNebCjPneCaeOaWkMtqWYeGo7zRz
         jReQ9iOfL7L55+LJd2/Lf8wZbMkZEe3zAtvkfErbOLRcMdiuugJnaAc29tiqr42puVzl
         mUEQo9Q9vPJCH51aegXH+kzUciX4ezzYOpEJyDH++BWMEXLZAJ1Gj1ZNTzmyGzfDucu/
         xWUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=om0mrHpb1JRAIkzCHzUIbq4iVPv837dvXWwLTffBx4I=;
        fh=bnMDFlB7I0KNYfUpVU4KIAAprJ7R80Qk1/jjpJa6GCo=;
        b=p6VVCE8KTCXhUtjvfZuYZUnyJyNESNYM1ehfT1fWtVdSqx8ER+04NeoUD3wZxlpa3a
         ikunr2c3aEQrpzA8Ffk5J+B2quwj7AE8UwXPZOdk67RmGLXyd/hz4KWX5odz9PbzRAhA
         bOnUtPb3QkcUvg2tKrOX2LCIwcje6ik4pFodznvrjPdQo+ZKj4g6fb4PyPIaK0RSr5dD
         2pI2lP8bh7aFYsLfFx4PdmxWpJvQwC+CcBdH4K4xyIr4doPAzDxF96RCUgpEd/wx0lNY
         kM8VoePayxH/+aQC4FKJqPN5lrS07UY4PP282a5imXC0oLczyIDnctaH793dFa/uy3pY
         w39A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=L72oIOQC;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::530 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722484888; x=1723089688; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=om0mrHpb1JRAIkzCHzUIbq4iVPv837dvXWwLTffBx4I=;
        b=PjRPIzYWg/qy3uKV1VWm+99l6SLMiXn1KvKFb3zKBJh/WdPa6OjQFJtjeYRryksj/f
         6IrzVAQmNbNydAeuf8p2OmL28hHsl46lXs9TZyfhMbdD1IvbUTmpIo2Q8+VkTabNLtIs
         W2WsKRfqrtXcNZKjisGTNpQfnyLUkqaz/W1qcuMvOUD04qLDwFMJht1E+VN0zIrKU4xS
         l4EIHthw3ojZES0NP6qwwoCrhYP0q5eiYpr6rSuLgSALzLVyQEEncprM221mAu+0TRCn
         CKsEs/QtoURQZz6kEwEF6ugwj92uEquPo/jLqF5xFZu255Xbo1irHr7uj8G69pvTEqiP
         f1eg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722484888; x=1723089688;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=om0mrHpb1JRAIkzCHzUIbq4iVPv837dvXWwLTffBx4I=;
        b=goAzXZSmJsPOGrnsiFKsw02j0FfgXHnfFelJisC1Zqc447tFnRR5AuDMgG1TG95Fzr
         RGqeMGZcu2o273XWIuql8V8fTHJ4xpcLNebjzieWbaq5k1ah9FsE3zlaOPH6k6FNE7UQ
         +ebRiPgT0ytMm+eJd3eUMpyWyV09yu71V+AyTlgzHmDvIPfHoby8ApJqoXJH/+sqGtPz
         XFQKqcRULtTCCiHlFelt3RY8H1Gqf9SLJSjeRYM63I7NPaxLU6G0a3Jv4oFoakWSwICK
         +0/vOafivjUIKJhqteBAwyedQMT2kToRRSGEgZFVHSWjgn2uUkbQjT/KvndGKjlWi44r
         wc2g==
X-Forwarded-Encrypted: i=2; AJvYcCV3Y7agcm2wTXaAsuhAOFQt/9FvXwEa8dokCdSh/xkcebNoNd5oSgcNVOHUZjed70U/+7tEsAmdiAWcFtNy/wBByi3UbFUqbQ==
X-Gm-Message-State: AOJu0YzDP11y186xUvP2apwVf1hC1NGIIiSu2aTK2Paou1++114AbIhe
	EJ+7ThRlRmZXf3VgwmUczXyFXrSdMzujJ5js5iJOE+atKs/STMy4
X-Google-Smtp-Source: AGHT+IGx+gBqA28wQWCKXgrF+AeLAfiN7vODBzVtFVxybk+vPiO8fd8Q6Iq9F1SgWxoz4HnPJwlxiA==
X-Received: by 2002:a05:600c:4450:b0:426:5ee3:728b with SMTP id 5b1f17b1804b1-428a9bdba7amr8113955e9.13.1722484887491;
        Wed, 31 Jul 2024 21:01:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:524e:b0:428:e09e:e808 with SMTP id
 5b1f17b1804b1-428e09ee9adls1550465e9.0.-pod-prod-01-eu; Wed, 31 Jul 2024
 21:01:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXHIXtGO4CSxe9v9yYFsqYQIXihyiZFeiV6nP00e9UisJGSo8KtkhWNoI1WkWh1qosaJA/K2QUH9AZrbnMW6oykkfCU3EQZtps9OA==
X-Received: by 2002:a05:600c:22d3:b0:426:61af:e1d3 with SMTP id 5b1f17b1804b1-428b8a37b90mr7814295e9.31.1722484885627;
        Wed, 31 Jul 2024 21:01:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722484885; cv=none;
        d=google.com; s=arc-20160816;
        b=pE5txY0It7rxplgL3rWCY8Cuo7xvqq/DsMHbgIFLE3sLm9B2TYuoyBLFfUI91i0qaI
         Bh6W5kVzKM4nyKMp3sTBvmY+wWrLyzSMYLndShYJJg713gXg2aZOORFFhyN+ddwiYRQs
         RTYaPTnYg0yiNfdAM5Qwpqp70R2w+8tVrh5iRdnWnZT5yI8OFycgd5CQj9vhzaqCP7OB
         iIDD4l12A7icGWPGC8BcSWH9uGUzybfv5BNus5XsEfOhahbPwcEdnJwwEYOb1ppgAZt9
         FWeNTF21ot5UqCyudpOP9mje4VLNlC+/JfjMNAkZlgU68Dksoo7EyCf49df5WXfjujAw
         /80Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=NT9JA8dx+64cxrNGE7PfVbIZYCFMvXqZQ2Ueee7W7a4=;
        fh=8MuoFb1hpusenSrAmJpaMjiUaf/AyC0b693l5Sji6xU=;
        b=nf7G7J3afB7lGXV2p0RvlAOQt7zVCERyE8S1UkBUuG2Yvuf9Qk0tG/dq5NzXIaINo/
         sY8xlW9BQvGEsJPdo7PrzYz4LqIyP+86AhA8OHkJWZ2W4zPhoL5VIR22VwKz9wjZy5Ov
         qhdzCGRSaFGs/uTvzus/FNpnc48gTtTzfoNNFkxGbczlNb3eBPFhXnCRY6xWb/u3x5Rg
         9yfg6yVRlDtU5VkYoKoGwfQKh0YA7Y1MvPAMnWSyD/INNGLF4la3bsJ7sj+1ccA0emcb
         Yu5plDZ6Axg0OKVxmmYROuaAcN/P2pxfQDCXJNAyHmjkt3+q6iSYXn5O/mQEk4i4QqPX
         hezg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=L72oIOQC;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::530 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x530.google.com (mail-ed1-x530.google.com. [2a00:1450:4864:20::530])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4282b5fbc2csi671835e9.0.2024.07.31.21.01.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 31 Jul 2024 21:01:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::530 as permitted sender) client-ip=2a00:1450:4864:20::530;
Received: by mail-ed1-x530.google.com with SMTP id 4fb4d7f45d1cf-5a18a5dbb23so27797a12.1
        for <kasan-dev@googlegroups.com>; Wed, 31 Jul 2024 21:01:25 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX4xed0Ks/Oq+MzlC7y10ayqw4uOjjPSoqi7yV4CatyX2d4wVkjXtd968yBPmqmdeqnT+dbTanoY0oF3C5D0VUbn+jcfZZ375TmTg==
X-Received: by 2002:a05:6402:4301:b0:58b:15e4:d786 with SMTP id
 4fb4d7f45d1cf-5b740990c57mr35420a12.5.1722484884423; Wed, 31 Jul 2024
 21:01:24 -0700 (PDT)
MIME-Version: 1.0
References: <20240730-kasan-tsbrcu-v5-0-48d3cbdfccc5@google.com>
 <20240730-kasan-tsbrcu-v5-1-48d3cbdfccc5@google.com> <CA+fCnZfURBYNM+o6omuTJyCtL4GpeudpErEd26qde296ciVYuQ@mail.gmail.com>
In-Reply-To: <CA+fCnZfURBYNM+o6omuTJyCtL4GpeudpErEd26qde296ciVYuQ@mail.gmail.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 1 Aug 2024 06:00:48 +0200
Message-ID: <CAG48ez12CMh2wM90EjF45+qvtRB41eq0Nms9ykRuf5-n7iBevg@mail.gmail.com>
Subject: Re: [PATCH v5 1/2] kasan: catch invalid free before SLUB
 reinitializes the object
To: Andrey Konovalov <andreyknvl@gmail.com>, Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>, 
	Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=L72oIOQC;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::530 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

(I'll address the other feedback later)

On Thu, Aug 1, 2024 at 2:23=E2=80=AFAM Andrey Konovalov <andreyknvl@gmail.c=
om> wrote:
>
> On Tue, Jul 30, 2024 at 1:06=E2=80=AFPM Jann Horn <jannh@google.com> wrot=
e:
> >
> > Currently, when KASAN is combined with init-on-free behavior, the
> > initialization happens before KASAN's "invalid free" checks.
> >
> > More importantly, a subsequent commit will want to RCU-delay the actual
> > SLUB freeing of an object, and we'd like KASAN to still validate
> > synchronously that freeing the object is permitted. (Otherwise this
> > change will make the existing testcase kmem_cache_invalid_free fail.)
> >
> > So add a new KASAN hook that allows KASAN to pre-validate a
> > kmem_cache_free() operation before SLUB actually starts modifying the
> > object or its metadata.
[...]
> > @@ -503,15 +509,22 @@ bool __kasan_mempool_poison_object(void *ptr, uns=
igned long ip)
> >                 kasan_poison(ptr, folio_size(folio), KASAN_PAGE_FREE, f=
alse);
> >                 return true;
> >         }
> >
> >         if (is_kfence_address(ptr))
> >                 return false;
> > +       if (!kasan_arch_is_ready())
> > +               return true;
>
> Hm, I think we had a bug here: the function should return true in both
> cases. This seems reasonable: if KASAN is not checking the object, the
> caller can do whatever they want with it.

But if the object is a kfence allocation, we maybe do want the caller
to free it quickly so that kfence can catch potential UAF access? So
"return false" in that case seems appropriate. Or maybe we don't
because that makes the probability of catching an OOB access much
lower if the mempool is going to always return non-kfence allocations
as long as the pool isn't empty? Also I guess whether kfence vetoes
reuse of kfence objects probably shouldn't depend on whether the
kernel is built with KASAN... so I guess it would be more consistent
to either put "return true" there or change the !KASAN stub of this to
check for kfence objects or something like that? Honestly I think the
latter would be most appropriate, though then maybe the hook shouldn't
have "kasan" in its name...

Either way, I agree that the current situation wrt mempools and kfence
is inconsistent, but I think I should probably leave that as-is in my
series for now, and the kfence mempool issue can be addressed
separately afterwards? I also would like to avoid changing kfence
behavior as part of this patch.

If you want, I can add a comment above the "if (is_kfence_address())"
that notes the inconsistency?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG48ez12CMh2wM90EjF45%2BqvtRB41eq0Nms9ykRuf5-n7iBevg%40mail.gmai=
l.com.
