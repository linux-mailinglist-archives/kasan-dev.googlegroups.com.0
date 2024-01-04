Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKUX3KWAMGQEOQRE23Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id AB8FC823F9A
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Jan 2024 11:42:52 +0100 (CET)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-427b6c5d8fasf1062471cf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Jan 2024 02:42:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704364971; cv=pass;
        d=google.com; s=arc-20160816;
        b=xxs8gAhTqxvhjL0aRm6gRpTD3YIpQvEn1RtsLq2aYOnpDwT/Kv7UjqeSVLVvceojry
         482pZB2qRvKcF/Vc3SBjl0GMimxg4com32FQPdcWuO5cqaqQBCaVy3fDr46qLVckBRaR
         Oxc06Uaa5aSh61YFjJwWrLip09kEvC8ORFPuyCzaGx3AEQM37j0h/LHL92ZxwCLUaPTe
         OkvpbOi1ka0/3+iSueS8XhavknJshvJxopsT+M7Eh/4+ZWraDXzw2/nDLW50ZGuD1FyC
         4Mbc03QeuvCxSTL0gSSv9W3eI6+kHh6+f2+Pkq6Kda9oDKAPmDzC6eJqv1jdR/AD3d/O
         Xl8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=VPNhuEayzu+Gz3TyexWQmR4T/otV4S5v1pHtqD/iX7I=;
        fh=AnoIy5yXpmYRAA/ZJLVC0D5vdVMFCXYVFmK8go1Xijw=;
        b=joHlGzs2z15GnMhsymSgz5CJ45Ilt2RbX+NE2ylYciIUJO1SYaWfSzdvAti6fgh4Kh
         lDRCyp9BL8T8cHSgXu4z5enhdZ95AvUiCaTD09lQu/LN1Y/N+R4c1jI5dXlbq8UjgSPY
         K3YudFyNRU6wu2B0k7n3gU10Z2YZ5SQyGhNZlp75DfnoQ4JFMG3MSYwaRnpOiSUs5eAc
         Z8XQTOja6njmpWpsoirvifenWXqyVYCtgoFyC4jmNhpqswk1dp9RmhhOqx1LbO3b/Uu/
         vpMLaqDrmBtKg35x7e4TuIVIqDzWHUc31GpUgS7wcyrIhwYwWpT3jRIR2F7R4jQo7CGJ
         YQzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ZsRpdU7T;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704364971; x=1704969771; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=VPNhuEayzu+Gz3TyexWQmR4T/otV4S5v1pHtqD/iX7I=;
        b=g4Pgir3nI+dBIHZDzg4/HijDPhSOwXYmIhtkTOFlrdKltXNi4UIb9TmsDXFfQs5oDu
         6PN0cFPO6AycFfvkNnvaHks35f73hKo5isS19QNsQbxFeNrYGl5e2qR4acvw8h/kQCDV
         1tsxekfy5hwNhEZJyd83hHitxbyEcS/P3vPcGupm5wuW556tG22jB880fJkS8bZEase9
         cEISzyiMupj4I0GqaNneLhB75EDA3vWekOoaV1+lealEWknHcZEEdWX7yTZSz8gIFpv1
         zbZnh7H8MJKFOEJ9uKnkgZRj9gniI6s7OkBvjQbTBNZzmrpNsyShWFD6Es4pOOYmHYKY
         RA4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704364971; x=1704969771;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VPNhuEayzu+Gz3TyexWQmR4T/otV4S5v1pHtqD/iX7I=;
        b=kiDgC0k+ekBC5665ieSPLqk43YQ3nYvRDdlpZhgux1gc10S6k0UFdjdKlLSfrlygbR
         zz0D/04yAxkNRIbwjMdXQQlwwKmTyzUrDCySoWyJgLoU/HuuHHtywRC6+aviZZgUBUmu
         gMQx02/dho0GVntp1ygMAJnOZ8Uf9pvTvX+k9jBcgUf/V/CsjhQLygx2F7Coc8EKaxxl
         o/i/DtpHbK99b0c4zEmOgsdDAfOQET3OqeiW+zdqgSDPpNX52r4rmvbkXKg+hWybtHQs
         za2amvKVAQHdSlp8x2sYHMG3aW/pPViU9LXF7mNfnlkaEsMLo3RKj9rnEEBZPj1jbveg
         wx8A==
X-Gm-Message-State: AOJu0YzVjTEEMmwZM2QTyqR2O4XlqMkG0oXB+8Ic5X+0Hz8iuaEn1yF2
	VtmAPOd7xUxHt/UTPdTYmyk=
X-Google-Smtp-Source: AGHT+IHMdd9hTw/Syv1Vr0Out21ekVlpzVAJEqEyC0HgUrRKJHzHu8bIHkPtQ1OcyBm4qRsTX/b+3g==
X-Received: by 2002:a05:6214:29ea:b0:680:d233:9cf with SMTP id jv10-20020a05621429ea00b00680d23309cfmr724187qvb.3.1704364971084;
        Thu, 04 Jan 2024 02:42:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5c6a:0:b0:67f:da:bf48 with SMTP id i10-20020ad45c6a000000b0067f00dabf48ls4672865qvh.1.-pod-prod-08-us;
 Thu, 04 Jan 2024 02:42:50 -0800 (PST)
X-Received: by 2002:a05:6214:2345:b0:680:a46:3d55 with SMTP id hu5-20020a056214234500b006800a463d55mr356701qvb.111.1704364970198;
        Thu, 04 Jan 2024 02:42:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704364970; cv=none;
        d=google.com; s=arc-20160816;
        b=iZ078tfhyT7tSrwFJ/i76TWKh/vmt3Kz8RMdj6ZJkSzNHMIS0/ziljIEVUDXp/Vzha
         ytzb+mc0DHYDlthDEh9rSJGNxFXDhx2wmCU+z9LpQIzySBkvuujonditN9ejsFRnzQ3a
         JbcueM20ea3FYrZ5KmZc/8f4z1Rv6Dhi26gUMXVQZcI0as54FPvKllUMw6AbJWFDA6zd
         KWHSKk3AqVW01Acd+NG3/bqifGUQS5oCQjZFU4IK7RL4OXlvdV3Ilo3DDpSLffy9cjCG
         iKOcC0kzFCqZ+d7fLS7UPMcT1C/gF3FTNNyNQE1nTIP7rKPLW1/bRuSBEUFQF0TvGskM
         Iaeg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=LolWQ4Jrb+Z7IGxXTLsLvRDIA9OucvvsNX3g5Br+h1s=;
        fh=AnoIy5yXpmYRAA/ZJLVC0D5vdVMFCXYVFmK8go1Xijw=;
        b=pHHLZb/dNU+Hls2+/uoiR7J1dKVTP5b+ebxHd1U9yybVhxpqYrouY3jmJdnPtX3NfO
         xuTE7bltw2gsvKUTJSe+XN1dfO+12RlmlHMMdniJXnWnpvaP1WrxmCtuUbYs3TuCDlpL
         EGioMR0l47fc+kpA1GDz/WkC1WPQh+k5m4Ot9VRNBr7OPQMAyvnpHGocHYLmGvC/XdAt
         Me7YSTm2/YTufo7oHu2HxKiiI6YIPSLIrqES2wmdS9jmPVhmA5jsZ3Ct1B7JLTUUWAMp
         rAo5srSC88c05pUTCDHCuFkC4DAFo4FND2HcuTJ0vvTS0Omhf30KhNxJ0+ZdH0i1dCWX
         3pbg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ZsRpdU7T;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa2b.google.com (mail-vk1-xa2b.google.com. [2607:f8b0:4864:20::a2b])
        by gmr-mx.google.com with ESMTPS id v12-20020ad4528c000000b0067f7f198909si2256838qvr.7.2024.01.04.02.42.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Jan 2024 02:42:50 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2b as permitted sender) client-ip=2607:f8b0:4864:20::a2b;
Received: by mail-vk1-xa2b.google.com with SMTP id 71dfb90a1353d-4b7153b8d76so88632e0c.0
        for <kasan-dev@googlegroups.com>; Thu, 04 Jan 2024 02:42:50 -0800 (PST)
X-Received: by 2002:a05:6122:3181:b0:4b6:e60e:e080 with SMTP id
 ch1-20020a056122318100b004b6e60ee080mr162069vkb.30.1704364969684; Thu, 04 Jan
 2024 02:42:49 -0800 (PST)
MIME-Version: 1.0
References: <cover.1700502145.git.andreyknvl@google.com> <1d1ad5692ee43d4fc2b3fd9d221331d30b36123f.1700502145.git.andreyknvl@google.com>
 <ZZZx5TpqioairIMP@localhost.localdomain> <CANpmjNMWyVOvni-w-2Lx6WyEUnP+G_cLVELJv_-B4W1fMrQpnw@mail.gmail.com>
 <ZZaGHbaerKfli0Wu@localhost.localdomain>
In-Reply-To: <ZZaGHbaerKfli0Wu@localhost.localdomain>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 4 Jan 2024 11:42:11 +0100
Message-ID: <CANpmjNMgpcpTCqepjQa=M7USYmCRYnRFRQdXfz0iZdPaBNK=6w@mail.gmail.com>
Subject: Re: [PATCH v4 17/22] lib/stackdepot: allow users to evict stack traces
To: Oscar Salvador <osalvador@suse.de>
Cc: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=ZsRpdU7T;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2b as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, 4 Jan 2024 at 11:18, Oscar Salvador <osalvador@suse.de> wrote:
>
> On Thu, Jan 04, 2024 at 10:25:40AM +0100, Marco Elver wrote:
> > I think a boolean makes the interface more confusing for everyone
> > else. At that point stack_depot_put merely decrements the refcount and
> > becomes a wrapper around refcount_dec, right?
>
> Thanks Marco for the feedback.
>
> Fair enough.
>
> > I think you want to expose the stack_record struct anyway for your
> > series, so why not simply avoid calling stack_depot_put and decrement
> > the refcount with your own helper (there needs to be a new stackdepot
> > function to return a stack_record under the pool_rwlock held as
> > reader).
>
> Yeah, that was something I was experimenting with my last version.
> See [0], I moved the "stack_record" struct into the header so page_owner
> can make sense of it. I guess that's fine right?

Not exposing the internals would be better, but at this point I think
your usecase looks like it's doing something that is somewhat out of
the bounds of the stackdepot API. I also don't see that it makes sense
to add more helpers to the stackdepot API to deal with such special
cases.

As such, I'd reason that it's ok to expose the struct for this special usecase.

> If so, I'd do as you mentioned, just decrementing it with my own helper
> so no calls to stack_depot_put will be needed.
>
> Regarding the locking, I yet have to check the patch that implements
> the read/write lock, but given that page_owner won't be evicting
> anything, do I still have to fiddle with the locks?

You need to grab the lock as a reader to fetch the stack_record and
return it. All that should be hidden behind whatever function you'll
introduce to return the stack_record (stack_depot_find()?).

> > Also, you need to ensure noone else calls stack_depot_put on the stack
> > traces you want to keep. If there is a risk someone else may call
> > stack_depot_put on them, it obviously won't work (I think the only
> > option then is to introduce a way to pin stacks).
>
> Well, since page_owner won't call stack_depot_put, I don't see
> how someone else would be able to interfere there, so I think
> I am safe there.
>
> [0] https://patchwork.kernel.org/project/linux-mm/patch/20231120084300.4368-3-osalvador@suse.de/
>
> --
> Oscar Salvador
> SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMgpcpTCqepjQa%3DM7USYmCRYnRFRQdXfz0iZdPaBNK%3D6w%40mail.gmail.com.
